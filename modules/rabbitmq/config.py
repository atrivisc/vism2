import os
from typing import ClassVar
from pydantic.dataclasses import dataclass
from lib.data.exchange import DataExchangeConfig


@dataclass
class RabbitMQConfig(DataExchangeConfig): # pylint: disable=too-many-instance-attributes
    """Configuration for RabbitMQ module."""

    __path__: ClassVar[str] = "rabbitmq"
    __config_dir__: ClassVar[str] = f"{os.getenv("CONFIG_DIR", os.getcwd()).rstrip("/")}"
    __config_file__: ClassVar[str] = f"{__config_dir__}/rabbitmq.yaml"

    host: str
    port: int
    user: str
    password: str
    vhost: str

    csr_queue: str = None
    cert_queue: str = None
    csr_exchange: str = None
    cert_exchange: str = None

    max_retries: int = 5
    retry_delay_seconds: int = 1

LOGGING_SENSITIVE_PATTERNS = {}
