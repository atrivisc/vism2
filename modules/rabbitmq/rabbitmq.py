"""RabbitMQ module for secure message exchange in VISM."""

import asyncio
import json
from typing import Callable, Awaitable

import aio_pika
from aio_pika import Message
from aio_pika.abc import AbstractIncomingMessage, AbstractRobustConnection, AbstractRobustChannel
from aiormq import AMQPConnectionError

from modules import module_logger
from modules.rabbitmq.config import RabbitMQConfig
from modules.rabbitmq.errors import RabbitMQError
from vism_lib.data.exchange import (
    DataExchange,
    DataExchangeCSRMessage,
    DataExchangeMessage,
    DataExchangeCertMessage
)

type AsyncCallableExchange = Callable[[DataExchangeMessage], Awaitable]
type AsyncCallableExchangeCSR = Callable[[DataExchangeCSRMessage], Awaitable]
type AsyncCallableExchangeCert = Callable[[DataExchangeCertMessage], Awaitable]


def rabbitmq_callback_decorator(original_function):
    def decorator(callback: AsyncCallableExchangeCSR | AsyncCallableExchangeCert):
        async def wrapper(message: AbstractIncomingMessage):
            message_body_dict = await original_function(message)

            exchange_message_class = callback.__annotations__.get('message', None)
            if not exchange_message_class:
                raise RabbitMQError(f"Invalid callback function: {callback.__name__}. Function does not have valid message arg annotation.")

            exchange_message = exchange_message_class(**message_body_dict)

            return await callback(exchange_message)

        return wrapper

    return decorator


class RabbitMQ(DataExchange):
    """RabbitMQ implementation of DataExchange."""
    configClass = RabbitMQConfig
    config: RabbitMQConfig

    def __init__(self, *args, **kwargs):
        module_logger.debug("Initializing RabbitMQ module")
        super().__init__(*args, **kwargs)

        self._connection: AbstractRobustConnection | None = None
        self._channel: AbstractRobustChannel | None = None

    async def get_channel(self):
        if self._connection is None or self._connection.is_closed:
            self._connection = await self.get_connection()

        if self._channel is None or self._channel.is_closed:
            self._channel = await self._connection.channel(on_return_raises=True)

        return self._channel

    async def cleanup(self, full: bool = False):
        """Clean up RabbitMQ resources."""
        module_logger.debug("Cleaning up RabbitMQ")
        if full:
            if self._channel is not None and not self._channel.is_closed:
                await asyncio.shield(self._channel.close())
            if self._connection is not None and not self._connection.is_closed:
                await asyncio.shield(self._connection.close())

    async def send_message(self, message: DataExchangeMessage, exchange_name: str, message_type: str, routing_key: str = ""):
        module_logger.info("Sending message to RabbitMQ exchange '%s'", exchange_name)

        data_json = message.to_json().encode("utf-8")
        message_signature = self.validation_module.sign(data_json)

        channel = await self.get_channel()
        if not channel.is_initialized:
            await channel.initialize(timeout=30)

        exchange = await channel.get_exchange(exchange_name)

        rabbitmq_message: Message = Message(
            body=data_json,
            headers={
                "X-Vism-Message-Type": message_type,
                "X-Vism-Signature": message_signature,
                "Content-Type": "application/octet-stream",
            }
        )

        try:
            await exchange.publish(message=rabbitmq_message, routing_key=routing_key)
        except Exception as e:
            module_logger.error(f"Failed to publish message: {e}")
            raise RuntimeError from e

    async def send_cert(self, message: DataExchangeCertMessage):
        await self.send_message(message, self.config.cert_exchange, "cert", self.config.cert_routing_key)

    async def send_csr(self, message: DataExchangeCSRMessage):
        await self.send_message(message, self.config.csr_exchange, "csr", self.config.csr_routing_key)

    async def _consume(self, *, queue_name, retry_count: int = 0, callback: AsyncCallableExchangeCSR | AsyncCallableExchangeCert):
        module_logger.info(
            "Starting listening for messages from RabbitMQ queue '%s'",
            queue_name
        )
        channel = await self.get_channel()
        if not channel.is_initialized:
            await channel.initialize(timeout=30)

        await channel.set_qos(prefetch_count=1)
        queue = await channel.declare_queue(
            name=queue_name,
            passive=True,
            durable=True,
            robust=True,
        )

        try:
            decorated_callback = rabbitmq_callback_decorator(self.handle_message)(callback)
            await queue.consume(decorated_callback)
        except AMQPConnectionError:
            if retry_count >= self.config.max_retries:
                raise
            await asyncio.sleep(self.config.retry_delay_seconds)
            return await self._consume(queue_name=queue_name, retry_count=retry_count, callback=callback)


    async def receive_cert(self, *, retry_count: int = 0, callback: AsyncCallableExchangeCert) -> None:
        await self._consume(queue_name=self.config.cert_queue, retry_count=retry_count, callback=callback)

    async def receive_csr(self, *, retry_count: int = 0, callback: AsyncCallableExchangeCSR) -> None:
        await self._consume(queue_name=self.config.csr_queue, retry_count=retry_count, callback=callback)

    async def handle_message(self, message: AbstractIncomingMessage) -> dict:
        module_logger.info("Received message from RabbitMQ.")
        async with message.process():
            message_type = message.headers.get("X-Vism-Message-Type", None)
            if message_type is None:
                raise RabbitMQError(f"No message type found in message headers: {message.headers}.")

            module_logger.info("Processing message from RabbitMQ of type '%s'.", message_type)
            module_logger.debug("Message body: %s | Signature: %s", message.body, message.headers['X-Vism-Signature'])

            if not self.validation_module.verify(message.body, message.headers["X-Vism-Signature"]):
                raise RabbitMQError('Invalid signature')

            return json.loads(message.body)

    async def get_connection(self) -> AbstractRobustConnection:
        try:
            return await aio_pika.connect_robust(
                host=self.config.host,
                port=self.config.port,
                login=self.config.user,
                password=self.config.password,
                virtualhost=self.config.vhost,
            )
        except AMQPConnectionError as e:
            raise RabbitMQError(
                f"Failed to connect to RabbitMQ: {e}"
            ) from e
