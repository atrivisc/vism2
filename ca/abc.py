import asyncio
from typing import Protocol, Any, Callable, Awaitable, TypeVar
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