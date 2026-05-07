
"""Database models for ACME authorization entities."""

from datetime import datetime, timedelta
from enum import Enum
from uuid import UUID

from sqlalchemy import String, ForeignKey, Uuid, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from vism_lib.database import Base
from vism_lib.util import absolute_url
from .order import OrderEntity
from .error import ErrorEntity


class IdentifierType(str, Enum):
    """Enumeration of ACME identifier types."""

    DNS = "dns"
    IP = "ip"


class AuthzStatus(str, Enum):
    """Enumeration of ACME authorization statuses."""

    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ChallengeStatus(str, Enum):
    """Enumeration of ACME challenge statuses."""

    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


def get_expiry_time():
    return (datetime.now() + timedelta(hours=12)).isoformat()

class AuthzEntity(Base):
    """Database entity representing an ACME authorization."""

    __tablename__ = 'authz'

    identifier_type: Mapped[IdentifierType] = mapped_column(String(32))
    identifier_value: Mapped[str] = mapped_column(String(256))
    status: Mapped[AuthzStatus] = mapped_column(String(32))
    wildcard: Mapped[bool] = mapped_column(Boolean)
    expires: Mapped[str] = mapped_column(
        String(64),
        default_factory=get_expiry_time,
        init=False
    )

    error_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey('error.id'),
        init=False,
        nullable=True,
        default=None
    )
    error: Mapped[ErrorEntity] = relationship(
        "ErrorEntity", lazy="joined", init=False, default=None
    )
    order_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey('order.id'), init=False
    )
    order: Mapped[OrderEntity] = relationship(
        "OrderEntity", lazy="joined"
    )

    def to_dict(self):
        """Convert authorization entity to dictionary representation."""
        return {
            "identifier_type": self.identifier_type,
            "identifier_value": self.identifier_value,
            "status": self.status,
            "wildcard": self.wildcard,
            "expires": self.expires,
            "error_id": str(self.error_id),
            "order_id": str(self.order_id),
        }


class ChallengeEntity(Base):
    """Database entity representing an ACME challenge."""

    __tablename__ = 'challenge'

    type: Mapped[str] = mapped_column(String(32))
    key_authorization: Mapped[str] = mapped_column(String(256))
    status: Mapped[ChallengeStatus] = mapped_column(String(32))

    authz_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey('authz.id'), init=False
    )
    authz: Mapped[AuthzEntity] = relationship(
        "AuthzEntity", lazy="joined"
    )

    def to_dict(self):
        """Convert challenge entity to dictionary representation."""
        return {
            "type": self.type,
            "key_authorization": self.key_authorization,
            "status": self.status,
            "authz_id": str(self.authz_id),
        }

    def to_reply_dict(self, request=None):
        """Convert challenge entity to reply in dictionary format."""
        data = {
            "type": self.type,
            "token": self.key_authorization.split('.')[0],
            "status": self.status,
        }
        if request:
            data["url"] = absolute_url(request, f"/challenge/{self.id}")
        return data
