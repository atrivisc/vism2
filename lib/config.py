"""Shared configuration classes for VISM components."""

import logging
from abc import ABCMeta
from dataclasses import field
from typing import ClassVar, Any, Self

import yaml
from cachetools import TTLCache
from pydantic import field_validator
from pydantic.dataclasses import dataclass

from lib.logs import LoggingConfig

shared_logger = logging.getLogger("vism_shared")

@dataclass
class DatabaseConfig:
    """Database connection configuration."""

    data_validation_key: str
    host: str = ""
    port: int = 3306
    database: str = ""
    username: str = ""
    password: str = ""
    driver: str = "postgresql+psycopg2"

    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, v):
        """Validate that port is in valid range."""
        if v < 1 or v > 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v

@dataclass
class DataExchange:
    """Configuration for data exchange module."""

    __path__: ClassVar[str] = "data_exchange"

    module: str
    validation_key: str = None

@dataclass
class Security:
    """Security configuration including validation and encryption."""

    __path__: ClassVar[str] = "security"

    data_exchange: DataExchange = None
    chroot_base_dir: str = None

@dataclass
class Config(metaclass=ABCMeta):
    """Abstract VISM configuration."""

    __path__: ClassVar[str] = ""
    __config_dir__: ClassVar[str] = ""
    __config_file__: ClassVar[str] = ""
    __ttl_cache__: ClassVar[TTLCache] = TTLCache(maxsize=5, ttl=10)

    @classmethod
    def load(cls) -> 'Self':
        return cls(**cls.read_config().get(cls.__path__, {}))

    @classmethod
    def read_config(cls) -> dict[str, Any]:
        if not cls.__ttl_cache__.get(cls.__config_file__):
            with open(cls.__config_file__, 'r') as config_file:
                cls.__ttl_cache__[cls.__config_file__] = yaml.safe_load(config_file)

        return cls.__ttl_cache__[cls.__config_file__]

@dataclass
class S3Config:
    """Configuration for s3."""

    __path__: ClassVar[str] = "s3"

    bucket: str
    endpoint: str
    access_key: str
    secret_key: str
    region: str = ""

@dataclass
class VismConfig(Config):
    """Base configuration class for VISM components."""

    security: Security = field(default_factory=Security)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    database: DatabaseConfig = None
    s3: S3Config = None
