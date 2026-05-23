import asyncio
from typing import Protocol, Any, Callable, Awaitable

type AsyncCallable = Callable[[], Awaitable]

class KeysProtocol(Protocol):

    def sign_data(self, privkey: Any, data: bytes, hash_alg_name: str) -> bytes: ...

    def generate_or_load_keypair(self, pub_key: Any, priv_key: Any) -> tuple[Any, Any]: ...

class Signer(Protocol):
    def sign(self, data: bytes, hash_algorithm: str) -> bytes:
        """Returns raw signature bytes."""
        ...

class Election(Protocol):
    shutdown_event: asyncio.Event
    is_leader: bool = False
    election_interval: int = 30

    async def follower_heartbeat(self):
        """Function called for follower on each loop in election_loop"""
        ...

    async def leader_heartbeat(self):
        """Function called for leader on each loop in election_loop"""
        ...

    async def resign(self, resign_callback: AsyncCallable):
        """Function called when leader resigns"""
        ...

    async def run(self, resign_callback: AsyncCallable, leader_callback: AsyncCallable, follower_callback: AsyncCallable):
        """Runs an infinite asyncio election loop"""
        ...