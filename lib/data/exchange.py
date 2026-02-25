"""Data exchange module for inter-component communication."""

import json
from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from lib.config import Config, shared_logger
from lib.data.validation import DataValidation


@dataclass
class DataExchangeConfig(Config):
    """Base configuration class for data exchange modules."""
    data_validation_key: str

@dataclass
class DataExchangeMessage:
    """Base class for data exchange messages."""

    def to_json(self) -> str:
        """Convert message to JSON string."""
        raise NotImplementedError()


@dataclass
class DataExchangeCSRMessage(DataExchangeMessage):
    """Message containing Certificate Signing Request data."""

    csr_pem: str
    ca_name: str
    days: int
    module_args: dict
    order_id: str
    profile_name: str = None

    def to_json(self) -> str:
        """Convert CSR message to JSON string."""
        return json.dumps({
            "csr_pem": self.csr_pem,
            "ca_name": self.ca_name,
            "days": self.days,
            "module_args": self.module_args,
            "order_id": self.order_id,
        })


@dataclass
class DataExchangeCertMessage(DataExchangeMessage):
    """Message containing certificate chain data."""

    chain: str
    order_id: str
    ca_name: str
    days: int
    original_signature: str

    def to_json(self) -> str:
        """Convert certificate message to JSON string."""
        return json.dumps({
            "chain": self.chain,
            "order_id": self.order_id,
            "ca_name": self.ca_name,
            "days": self.days,
            "original_signature": self.original_signature,
        })


class DataExchange(metaclass=ABCMeta):
    """Abstract base class for data exchange implementations."""

    configClass = DataExchangeConfig

    def __init__(self, controller):
        shared_logger.debug(
            "Initializing DataExchange module: %s",
            self.__class__.__name__
        )
        self.controller = controller
        self.config: DataExchangeConfig = self.configClass.load()
        self.validation_module = DataValidation(validation_key=self.config.data_validation_key)

    async def cleanup(self, full: bool = False):
        """Clean up resources used by the data exchange module."""

    @abstractmethod
    async def send_csr(self, message: DataExchangeCSRMessage):
        """Send a CSR message to the CA."""
        raise NotImplementedError()

    @abstractmethod
    async def send_cert(self, message: DataExchangeCertMessage):
        """Send certificate data."""
        raise NotImplementedError()

    @abstractmethod
    async def receive_csr(self) -> None:
        """Receive CSR data from clients."""
        raise NotImplementedError()

    @abstractmethod
    async def receive_cert(self) -> None:
        """Receive certificate data from CA."""
        raise NotImplementedError()
