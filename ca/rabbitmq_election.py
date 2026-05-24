"""Main Vism CA class and entrypoint."""

import asyncio
import aio_pika
from vism_lib.rabbitmq import RabbitMQClient
from ca.abc import Election
from ca.config import ca_logger

class RabbitMQElection(Election):
    def __init__(self, shutdown_event: asyncio.Event, election_interval: int = 30, *, rabbitmq_client: RabbitMQClient, leader_queue: str):
        self.shutdown_event = shutdown_event
        self.election_interval = election_interval

        self.is_leader = False
        self._leader_queue = leader_queue
        self._rabbitmq_client = rabbitmq_client

        super().__init__()

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

    async def resign(self) -> None:
        if self.is_leader:
            ca_logger.info("Resigning as leader.")
            self.is_leader = False

        await self._rabbitmq_client.close()
        await self.notify_handler("on_resign")

    async def run(self):
        try:
            while not self.shutdown_event.is_set():
                if not self.is_leader:
                    won = await self._try_become_leader()
                    if not won:
                        await self.notify_handlers(events=["on_follower_heartbeat", "on_election_lost"])
                        await asyncio.sleep(self.election_interval)
                    else:
                        await self.notify_handler("on_elected")
                else:
                    channel = await self._rabbitmq_client.channel()
                    if channel and channel.is_closed:
                        ca_logger.warning("Lost leader channel — re-entering election")
                        self.is_leader = False
                        continue

                    await self.notify_handler("on_leader_heartbeat")
                    await asyncio.sleep(self.election_interval)
        except Exception as e:
            ca_logger.error(f"Stopping rabbitmq leadership loop: {e}")
            raise e
        finally:
            await self.resign()
            await self._rabbitmq_client.close()
