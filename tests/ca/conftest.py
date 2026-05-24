from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy import event as sa_event

from ca.database import VismCADatabase
from vism_lib.data.validation import DataValidation

from tests.ca._helpers import LocalKeyManager


@pytest.fixture
def db() -> VismCADatabase:
    engine = create_engine("sqlite:///:memory:")

    @sa_event.listens_for(engine, "connect")
    def _enable_fk(dbapi_conn, _connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    validation = DataValidation(validation_key="test-validation-key")
    return VismCADatabase(engine, validation)


@pytest.fixture
def key_manager() -> LocalKeyManager:
    return LocalKeyManager()
