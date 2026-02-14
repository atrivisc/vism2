# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Shared database models and utilities for VISM components."""

import json
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Generator, Type
from uuid import UUID, uuid4
from sqlalchemy import Uuid, String, DateTime, func
from sqlalchemy import ColumnExpressionArgument
from sqlalchemy.orm import (
    MappedAsDataclass,
    DeclarativeBase,
    Mapped,
    mapped_column,
    sessionmaker,
    Session
)
from sqlalchemy.engine import URL, create_engine
from lib.config import shared_logger, DatabaseConfig
from sqlalchemy.exc import OperationalError, StatementError
from sqlalchemy.orm.query import Query as _Query

from lib.data.validation import DataValidation
from lib.errors import VismDatabaseException


class Base(MappedAsDataclass, DeclarativeBase):
    """Base class for all database entities with common fields."""

    id: Mapped[UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid4, init=False
    )
    signature: Mapped[str] = mapped_column(
        String, nullable=True, default=None, init=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        init=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=func.now(),
        onupdate=func.now(),
        init=False
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert entity to dictionary representation."""
        raise NotImplementedError()

    def validate(self, validation_module: DataValidation) -> bool:
        """Validate entity signature using validation module."""
        shared_logger.info(
            "Validating %s %s",
            self.__class__.__name__,
            self.id
        )
        data_bytes = json.dumps(self.to_dict()).encode("utf-8")
        data_signature = validation_module.sign(data_bytes)
        return data_signature == self.signature


    def sign(self, validation_module: DataValidation) -> str:
        """Sign entity data using validation module."""
        shared_logger.info(
            "Signing %s %s",
            self.__class__.__name__,
            self.id
        )
        data_bytes = json.dumps(self.to_dict()).encode("utf-8")
        data_signature = validation_module.sign(data_bytes)
        return data_signature

class RetryingQuery(_Query):
    __max_retry_count__ = 3

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __iter__(self):
        attempts = 0
        while True:
            attempts += 1
            try:
                return super().__iter__()
            except OperationalError as ex:
                if "server closed the connection unexpectedly" not in str(ex):
                    raise
                if attempts <= self.__max_retry_count__:
                    continue
                else:
                    raise
            except StatementError as ex:
                if "reconnect until invalid transaction is rolled back" not in str(ex):
                    raise
                self.session.rollback()


class VismDatabase:
    """Database interface for VISM operations."""

    def __init__(self, database_config: DatabaseConfig):
        shared_logger.info("Initializing database")
        self.db_url = URL.create(
            drivername=database_config.driver,
            username=database_config.username,
            password=database_config.password,
            host=database_config.host,
            port=database_config.port,
            database=database_config.database
        )

        self.engine = create_engine(self.db_url, echo=False, pool_pre_ping=True)
        self.session_maker = sessionmaker(bind=self.engine, query_cls=RetryingQuery)
        self._create_tables()

        self.validation_module = DataValidation(validation_key=database_config.data_validation_key)

    def get(
            self,
            obj_type: Type[Base],
            *criterion: ColumnExpressionArgument[bool],
            multiple: bool = False
    ):
        """
        Get entity or entities from database by criteria.

        Args:
            obj_type: Type of entity to retrieve
            *criterion: Filter criteria
            multiple: Whether to return multiple results

        Returns:
            Single entity, list of entities, or None
        """
        with self._get_session() as session:
            objs: list[Base] = session.query(obj_type).filter(*criterion).all()
            for obj in objs:
                if not obj.validate(self.validation_module):
                    raise VismDatabaseException("Object has invalid signature")
            if not multiple:
                if len(objs) == 0:
                    return None
                if len(objs) > 1:
                    raise VismDatabaseException("Multiple objects found.")
                return objs[0]
            return objs

    def save_to_db(self, obj: Base):
        """
        Save entity to database with signature.

        Args:
            obj: Entity to save

        Returns:
            Saved entity with updated signature
        """
        with self._get_session() as session:
            merged = session.merge(obj)
            session.flush()
            merged.signature = merged.sign(self.validation_module)
            merged = session.merge(merged)
            session.flush()
            shared_logger.info(
                "Saved %s %s to database",
                merged.__class__.__name__,
                merged.id
            )
            return merged

    def _create_tables(self):
        """Create all database tables."""
        Base.metadata.create_all(self.engine)

    @contextmanager
    def _get_session(self) -> Generator[Session, Any, None]:
        """Get database session with automatic commit/rollback."""
        session = self.session_maker(expire_on_commit=False)
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
