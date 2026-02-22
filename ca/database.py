"""
Database module for Vism CA.

This module provides database models and operations for the Vism CA,
including certificate entities and database management.
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, Boolean, UUID, ForeignKey, Uuid, Integer, LargeBinary
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy.orm import mapped_column
from lib.database import Base, VismDatabase


class ModuleData:
    """Base class for module-specific data storage."""

class IssuedCertificate(Base):
    """Database entity representing an issued certificate."""

    __tablename__ = 'issued_certificate'

    status_flag: Mapped[str] = mapped_column(String)
    expiration_date: Mapped[bytes] = mapped_column(LargeBinary)
    serial: Mapped[bytes] = mapped_column(LargeBinary)
    subject: Mapped[bytes] = mapped_column(LargeBinary)

    ca_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey('certificate.id'), init=False)
    ca: Mapped[CertificateEntity] = relationship("CertificateEntity", lazy="joined", default=None)

    revocation_date: Mapped[bytes] = mapped_column(LargeBinary, nullable=True, default=None)

    def to_dict(self):
        """Convert entity to dictionary representation."""
        return {
            "status_flag": self.status_flag,
            "expiration_date": self.expiration_date.hex(),
            "serial": self.serial.hex(),
            "subject": self.subject.hex(),
            "ca_id": str(self.ca_id),
            "revocation_date": self.revocation_date.hex() if self.revocation_date else None,
        }

class CertificateEntity(Base):
    """Database entity representing a certificate."""

    __tablename__ = 'certificate'

    name: Mapped[str] = mapped_column(String)
    externally_managed: Mapped[bool] = mapped_column(Boolean)
    crl_number: Mapped[int] = mapped_column(Integer, default=1)

    crt_der: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True, default=None)
    crl_der: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True, default=None)

    def to_dict(self):
        """Convert entity to dictionary representation."""
        return {
            "name": self.name,
            "externally_managed": self.externally_managed,
            "crl_number": self.crl_number,
            "crt_der": self.crt_der.hex() if self.crt_der else None,
            "crl_der": self.crl_der.hex() if self.crl_der else None,
        }

class VismCADatabase(VismDatabase):
    """Database interface for Vism CA operations."""

    def get_cert_by_name(self, name: str) -> Optional[CertificateEntity]:
        """
        Get a certificate entity by name.

        Args:
            name: Certificate name to search for

        Returns:
            CertificateEntity if found, None otherwise
        """
        with self._get_session() as session:
            return session.query(CertificateEntity).filter(CertificateEntity.name == name).first()
