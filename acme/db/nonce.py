import secrets
from uuid import UUID

from sqlalchemy import String, ForeignKey, Uuid
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from vism_lib.database import Base
from .account import AccountEntity

def _new_nonce():
    return secrets.token_urlsafe(32)

class NonceEntity(Base):
    """Database entity representing an ACME order."""

    __tablename__ = 'nonce'
    nonce: Mapped[str] = mapped_column(String(32), default_factory=_new_nonce, init=False)

    account_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey('account.id'), init=False
    )
    account: Mapped[AccountEntity] = relationship(
        "AccountEntity", lazy="joined", default=None
    )
