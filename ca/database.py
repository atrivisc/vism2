from datetime import datetime
from typing import Optional
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_modules import rfc5280
from sqlalchemy import String, Boolean, UUID, ForeignKey, Uuid, Integer, LargeBinary, DateTime
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy.orm import mapped_column
from vism_lib.database import Base, VismDatabase
from vism_lib.errors import VismBreakingException, VismException


class ModuleData:
    """Base class for module-specific data storage."""

class IssuedCertificate(Base):
    """Database entity representing an issued certificate."""

    __tablename__ = 'issued_certificate'

    status_flag: Mapped[str] = mapped_column(String(8))
    expiration_date: Mapped[datetime] = mapped_column(DateTime)
    serial: Mapped[bytes] = mapped_column(LargeBinary)
    subject: Mapped[bytes] = mapped_column(LargeBinary)

    ca_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey('certificate.id'), init=False)
    ca: Mapped['CertificateEntity'] = relationship("CertificateEntity", back_populates="issued_certificates", lazy="joined", default=None)

    revocation_date: Mapped[datetime] = mapped_column(DateTime, nullable=True, default=None)
    revocation_reason: Mapped[str] = mapped_column(String(128), nullable=True, default=None)

    def to_dict(self):
        """Convert entity to dictionary representation."""
        return {
            "status_flag": self.status_flag,
            "expiration_date": str(self.expiration_date),
            "serial": self.serial.hex(),
            "subject": self.subject.hex(),
            "revocation_date": str(self.revocation_date) if self.revocation_date else None,
            "revocation_reason": self.revocation_reason if self.revocation_reason else None,
        }

class CertificateEntity(Base):
    """Database entity representing a certificate."""

    __tablename__ = 'certificate'

    name: Mapped[str] = mapped_column(String(256))
    externally_managed: Mapped[bool] = mapped_column(Boolean)

    signer_id: Mapped[Optional[UUID]] = mapped_column(Uuid, ForeignKey('certificate.id'), nullable=True, init=False)
    signer: Mapped[Optional['CertificateEntity']] = relationship("CertificateEntity", lazy="joined")

    crl_number: Mapped[int] = mapped_column(Integer, default=1)

    crt_der: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True, default=None)
    crl_der: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True, default=None)

    issued_certificates: Mapped[list[IssuedCertificate]] = relationship(
        "IssuedCertificate",
        back_populates="ca",
        lazy="selectin",
        cascade="all, delete-orphan",
        default_factory=list
    )

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

    def get_chain_ders(self, cert_name: str) -> list[bytes]:
        """Return DER bytes for cert_name and each of its signers, root last."""
        with self._get_session() as session:
            cert_entity = session.query(CertificateEntity).filter(CertificateEntity.name == cert_name).first()
            if cert_entity is None:
                raise VismException(f"Certificate {cert_name} not found in the database.")

            ders: list[bytes] = []
            while cert_entity is not None:
                if cert_entity.crt_der is None:
                    raise VismException(
                        f"Certificate {cert_entity.name} has no crt_der in the database."
                    )
                ders.append(cert_entity.crt_der)
                cert_entity = cert_entity.signer
            return ders

    def get_issued_certificate_by_serial(self, serial: int | str) -> Optional[IssuedCertificate]:
        # when str, assume it's a hex
        if isinstance(serial, str):
            try:
                serial = int(serial, 16)
            except ValueError:
                raise VismBreakingException(f"Invalid serial number: {serial}")

        serial_ans1 = rfc5280.CertificateSerialNumber(serial)

        with self._get_session() as session:
            return session.query(IssuedCertificate).filter(IssuedCertificate.serial == der_encoder(serial_ans1)).first()

    def get_revoked_certificates_for_issuer(self, issuer_id: UUID) -> list[IssuedCertificate]:
        with self._get_session() as session:
            return session.query(IssuedCertificate).filter(IssuedCertificate.ca_id == issuer_id, IssuedCertificate.status_flag == 'r').all()

    def get_issued_certificates(self, issuer_id: UUID) -> list[IssuedCertificate]:
        with self._get_session() as session:
            return session.query(IssuedCertificate).filter(IssuedCertificate.ca_id == issuer_id).all()

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
