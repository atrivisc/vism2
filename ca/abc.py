import asyncio
from abc import ABCMeta
from typing import Protocol, Any, Callable, Awaitable, TypeVar, ClassVar
type AsyncCallable = Callable[[], Awaitable]

class Key(Protocol):
    @property
    def label(self) -> str:
        ...

    @property
    def id(self) -> str:
        ...

    @property
    def key_type(self) -> Any:
        ...

    @property
    def key_length(self) -> int:
        ...

class PrivateKey(Key, Protocol):
    ...

class PublicKey(Key, Protocol):
    def public_bytes(self) -> bytes:
        """Returns der encoded public key bytes."""
        ...

PrivKeyT = TypeVar("PrivKeyT", bound=PrivateKey, contravariant=True)
PubKeyT = TypeVar("PubKeyT", bound=PublicKey, contravariant=True)

class KeyManager(Protocol[PrivKeyT, PubKeyT]):

    def sign_data_with_key(self, privkey: PrivKeyT, data: bytes, hash_alg_name: str) -> bytes: ...

    def generate_or_load_keypair(self, pub_key: PubKeyT, priv_key: PrivKeyT) -> tuple[PubKeyT, PrivKeyT]: ...

    def make_key_descriptors(self, cert_config: 'CertificateConfig') -> tuple[PubKeyT, PrivKeyT]: ...

class Election(metaclass=ABCMeta):
    shutdown_event: asyncio.Event
    is_leader: bool = False
    election_interval: int = 30
    handlers: dict[str, list[AsyncCallable]] = None

    EVENTS: ClassVar[list[str]] = [
        "on_follower_heartbeat",
        "on_leader_heartbeat",
        "on_resign",
        "on_leader_lost",
        "on_elected",
        "on_election_lost"
    ]

    def __init__(self):
        if self.handlers is None:
            self.handlers = {}

    def register_handler(self, event: str, handler: AsyncCallable):
        if event not in self.EVENTS:
            raise ValueError(f"Event {event} is not supported by this election")

        self.handlers.setdefault(event, []).append(handler)

    def unregister_handler(self, event: str, handler: AsyncCallable):
        if event not in self.EVENTS:
            raise ValueError(f"Event {event} is not supported by this election")

        if event not in self.handlers:
            return

        self.handlers[event].remove(handler)

    async def notify_handlers(self, events: list[str]):
        for event in events:
            await self.notify_handler(event)

    async def notify_handler(self, event: str):
        if event not in self.EVENTS:
            raise ValueError(f"Event {event} is not supported by this election")

        if event not in self.handlers:
            return

        for handler in self.handlers[event]:
            await handler()

    async def run(self):
        """Runs an infinite asyncio election loop"""
        raise NotImplementedError()
