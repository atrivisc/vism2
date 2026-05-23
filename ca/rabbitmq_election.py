"""Main Vism CA class and entrypoint."""

import asyncio
from datetime import datetime
import aio_pika
from vism_lib.rabbitmq import RabbitMQClient
from ca.abc import AsyncCallable, Election
from ca.config import ca_logger

class RabbitMQElection(Election):
    def __init__(self, shutdown_event: asyncio.Event, election_interval: int = 30, *, rabbitmq_client: RabbitMQClient, leader_queue: str):
        self.shutdown_event = shutdown_event
        self.election_interval = election_interval

        self.is_leader = False
        self._leader_queue = leader_queue
        self._rabbitmq_client = rabbitmq_client

    async def leader_heartbeat(self) -> None:
        now = datetime.now().strftime("%H:%M:%S")
        ca_logger.info(f"I am the leader — heartbeat at {now}")

    async def follower_heartbeat(self) -> None:
        ca_logger.info("Nothing to do — I am secondary")

    async def _try_become_leader(self) -> bool:
        try:
            channel = await self._rabbitmq_client.channel()
            queue = await channel.declare_queue(
                self._leader_queue,
                exclusive=True,
                auto_delete=True,
                durable=False,
            )

            await queue.consume(self._on_leader_message, no_ack=True)
            self.is_leader = True
            ca_logger.info("Won the election — I am now the leader")
            return True
        except aio_pika.exceptions.ChannelPreconditionFailed:
            return False
        except Exception as e:
            ca_logger.debug(f"Lost election round: {e}")
            await self._rabbitmq_client.close()
            return False

    async def _on_leader_message(self, *args, **kwargs):
        pass

    async def resign(self, resign_callback: AsyncCallable) -> None:
        if self.is_leader:
            ca_logger.info("Resigning as leader.")
            self.is_leader = False

        await self._rabbitmq_client.close()
        await resign_callback()

    async def run(self, resign_callback: AsyncCallable, leader_callback: AsyncCallable, follower_callback: AsyncCallable):
        try:
            while not self.shutdown_event.is_set():
                if not self.is_leader:
                    won = await self._try_become_leader()
                    if not won:
                        await self.follower_heartbeat()
                        await follower_callback()
                        await asyncio.sleep(self.election_interval)
                    else:
                        await leader_callback()
                else:
                    channel = await self._rabbitmq_client.channel()
                    if channel and channel.is_closed:
                        ca_logger.warning("Lost leader channel — re-entering election")
                        self.is_leader = False
                        continue

                    await self.leader_heartbeat()
                    await asyncio.sleep(self.election_interval)
        except Exception as e:
            ca_logger.error(f"Stopping rabbitmq leadership loop: {e}")
            raise e
        finally:
            await self.resign(resign_callback)
            await self._rabbitmq_client.close()
