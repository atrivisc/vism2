"""Base controller class for VISM components."""

import asyncio

from lib.config import Config, shared_logger, DataExchange
from lib.database import VismDatabase
from lib.logs import setup_logger, SensitiveDataFilter
from lib.s3 import AsyncS3Client


class Controller:
    """Base controller class for managing modules and configuration."""

    configClass = Config
    databaseClass = VismDatabase

    def __init__(self):
        self.config = self.configClass.load()
        self.setup_logging()
        self.database = self.databaseClass(self.config.database)
        self.s3 = AsyncS3Client(self.config.s3)
        self.data_exchange_module = None

        self._shutdown_event = asyncio.Event()

    def __post_init__(self):
        self.setup_logging()

    def setup_logging(self):
        """Set up logging configuration."""
        shared_logger.info("Setting up logging")
        setup_logger(self.config.logging)

    def shutdown(self):
        """Initiates shutdown of the CA."""
        shared_logger.info("Received shutdown signal, shutting down")
        self._shutdown_event.set()

    async def setup_data_exchange_module(self) -> DataExchange:
        """Set up the data exchange module from configuration."""
        data_exchange_module_imports = __import__(
            f'modules.{self.config.security.data_exchange.module}',
            fromlist=['Module', 'ModuleConfig']
        )

        SensitiveDataFilter.SENSITIVE_PATTERNS.update(
            data_exchange_module_imports.LOGGING_SENSITIVE_PATTERNS
        )

        self.data_exchange_module = data_exchange_module_imports.Module(self)
        return self.data_exchange_module
