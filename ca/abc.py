from typing import Protocol, Any


class KeysProtocol(Protocol):

    def sign_data(self, privkey: Any, data: bytes, hash_alg_name: str) -> bytes: ...

    def generate_or_load_keypair(self, pub_key: Any, priv_key: Any) -> tuple[Any, Any]: ...

class Signer(Protocol):
    def sign(self, data: bytes, hash_algorithm: str) -> bytes:
        """Returns raw signature bytes."""
        ...
