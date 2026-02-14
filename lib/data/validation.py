"""Data validation and cryptography module interfaces."""
import hashlib
import hmac
from dataclasses import dataclass
from lib.config import Config, shared_logger
from lib.errors import VismException


class DataError(VismException):
    """Exception raised for data validation/encryption errors."""


@dataclass
class DataModuleConfig:
    """Base configuration class for data modules."""


@dataclass
class DataConfig(Config):
    """Configuration class for data operations."""


class DataValidation:
    """Abstract base class for data validation and encryption modules."""

    def __init__(self, *, validation_key: str = None):
        shared_logger.info("Initializing Data module")
        self.validation_key = validation_key.encode("utf-8")

    def sign(self, data: bytes) -> str:
        """Sign data using the module's validation key."""
        return hmac.new(self.validation_key, data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, signature: str) -> bool:
        """Verify data signature using the module's validation key."""
        data_signature = self.sign(data)
        return hmac.compare_digest(data_signature, signature)
