"""Data vault storage module."""
from abc import abstractmethod, ABCMeta
from pydantic.dataclasses import dataclass
from lib.config import Config


@dataclass
class VaultConfig(Config):
    """Base class for vault module configuration."""


class Vault(metaclass=ABCMeta):
    """Base class for vault storage modules."""
    configClass = VaultConfig

    def __init__(self):
        self.config = self.configClass.load()

    @abstractmethod
    def get_secret(self, secret_path: str) -> str:
        """Get secret from a vault."""

    @abstractmethod
    def put_secret(self, secret_path: str, secret_value: bytes) -> None:
        """Put a secret into a vault."""
