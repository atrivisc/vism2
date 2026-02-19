"""
Database module for Vism CA.

This module provides database models and operations for the Vism CA,
including certificate entities and database management.
"""

from typing import Optional
from sqlalchemy import String, Text, Boolean, UUID, ForeignKey, Uuid, Integer
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy.orm import mapped_column
from lib.database import Base, VismDatabase


class ModuleData:
    """Base class for module-specific data storage."""

class IssuedCertificate(Base):
    """Database entity representing an issued certificate."""

    __tablename__ = 'issued_certificate'

    status_flag: Mapped[str] = mapped_column(String)
    expiration_date: Mapped[str] = mapped_column(String)
    revocation_date: Mapped[str] = mapped_column(String)
    serial_hex: Mapped[str] = mapped_column(String)
    distinguished_name: Mapped[str] = mapped_column(String)

    ca_id: Mapped[UUID] = mapped_column(
        Uuid, ForeignKey('certificate.id'), init=False
    )
    ca: Mapped[CertificateEntity] = relationship(
        "CertificateEntity", lazy="joined", default=None
    )

class CertificateEntity(Base):
    """Database entity representing a certificate."""

    __tablename__ = 'certificate'

    name: Mapped[str] = mapped_column(String)
    externally_managed: Mapped[bool] = mapped_column(Boolean)
    crl_number: Mapped[int] = mapped_column(Integer, default=1)

    crt_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    crl_pem: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)

    def to_dict(self):
        """Convert entity to dictionary representation."""
        return {
            "name": self.name,
            "externally_managed": self.externally_managed,
            "crt_pem": self.crt_pem,
            "crl_pem": self.crl_pem,
        }

    def cert_data(self):
        """Get certificate data for external use."""
        return {
            "name": self.name,
            "crt_pem": self.crt_pem,
            "crl_pem": self.crl_pem,
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
