import os
from typing import ClassVar
from pydantic.dataclasses import dataclass
from vism_lib.data.exchange import DataExchangeConfig


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

    csr_routing_key: str
    cert_routing_key: str
    csr_queue: str
    cert_queue: str
    csr_exchange: str
    cert_exchange: str

    max_retries: int = 5
    retry_delay_seconds: int = 1

LOGGING_SENSITIVE_PATTERNS = {}
