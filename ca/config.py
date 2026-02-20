"""
Configuration module for Vism CA.

This module provides configuration classes for the CA, including database
configuration, certificate configuration, and the main CA configuration class.
"""
import enum
import hashlib
import ipaddress
import logging
import os
from typing import ClassVar, Any
import idna
import pkcs11
from cryptography import x509
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.x509 import RFC822Name, IPAddress, DNSName, DirectoryName, Name, UniformResourceIdentifier
from pkcs11.util.ec import encode_named_curve_parameters
from pyasn1.type import univ
from pyasn1_modules.rfc2986 import RDNSequence, RelativeDistinguishedName, AttributeTypeAndValue
from pydantic import field_validator
from pydantic.dataclasses import dataclass
from ca.errors import CertConfigNotFound
from lib.config import VismConfig

logger = logging.getLogger(__name__)
ca_logger = logging.getLogger("vism_ca")

class SupportedKeyAlgorithms(enum.Enum):
    """Supported key algorithms."""
    rsa = "RSA"
    ec = "EC"


@dataclass
class KeyConfig:
    """OpenSSL key generation configuration."""
    algorithm: SupportedKeyAlgorithms
    curve: str = None
    bits: int = None

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str):
        if v not in [SupportedKeyAlgorithms.rsa, SupportedKeyAlgorithms.ec]:
            raise ValueError(f"Unsupported key algorithm: {v}")

        return v

    @field_validator("bits")
    @classmethod
    def validate_rsa_bits(cls, v: int):
        """Validate RSA key size."""
        if v is None:
            return v

        if not 2048 <= v <= 8192:
            raise ValueError(f"RSA key size must be between 2048 and 8192 bits, got {v}")

        return v


@dataclass
class CertificateCryptoConfig:
    """Configuration for a certificate crypto module."""
    cn: str = None
    days: int = None


@dataclass
class PKCS11Config:
    """PKCS#11 configuration."""
    lib_path: str
    token_label: str
    user_pin: str

    @field_validator("lib_path")
    @classmethod
    def validate_lib_path(cls, v: str):
        """Validate PKCS#11 library path."""
        if not os.path.exists(v):
            raise ValueError(f"PKCS#11 library path '{v}' does not exist")

        return v

@dataclass
class X509ConfigSubjectName:
    """X509 subject name configuration."""
    common_name: str = None
    country: str = None
    state_or_province: str = None
    locality: str = None
    organization: str = None

    @staticmethod
    def _add_rdn(rdn_seq: RDNSequence, attribute_type: ObjectIdentifier, value: str):
        if value:
            rdn = RelativeDistinguishedName()
            attr = AttributeTypeAndValue()
            attr.setComponentByName("type", univ.ObjectIdentifier(attribute_type.dotted_string))
            attr.setComponentByName("value", univ.OctetString(value))
            rdn.append(attr)
            rdn_seq.append(rdn)

    def to_rdn_seq(self):
        rdn_seq = RDNSequence()

        self._add_rdn(rdn_seq, x509.NameOID.COMMON_NAME, self.common_name)
        self._add_rdn(rdn_seq, x509.NameOID.COUNTRY_NAME, self.country)
        self._add_rdn(rdn_seq, x509.NameOID.STATE_OR_PROVINCE_NAME, self.state_or_province)
        self._add_rdn(rdn_seq, x509.NameOID.LOCALITY_NAME, self.locality)
        self._add_rdn(rdn_seq, x509.NameOID.ORGANIZATION_NAME, self.organization)

        return rdn_seq

@dataclass
class X509ConfigKeyUsage:
    """X509 key usage configuration."""
    digital_signature: bool = False
    content_commitment: bool = False
    key_encipherment: bool = False
    data_encipherment: bool = False
    key_agreement: bool = False
    key_cert_sign: bool = False
    crl_sign: bool = False
    encipher_only: bool = False
    decipher_only: bool = False
    critical: bool = False

    def to_obj(self):
        return x509.KeyUsage(
            digital_signature=self.digital_signature,
            content_commitment=self.content_commitment,
            key_encipherment=self.key_encipherment,
            data_encipherment=self.data_encipherment,
            key_agreement=self.key_agreement,
            key_cert_sign=self.key_cert_sign,
            crl_sign=self.crl_sign,
            encipher_only=self.encipher_only,
            decipher_only=self.decipher_only,
        )

@dataclass
class X509ConfigExtendedKeyUsage:
    usages: list[str]
    critical: bool = False

    def to_obj(self):
        usages = [ObjectIdentifier(usage) for usage in self.usages]
        return x509.ExtendedKeyUsage(usages=usages)

@dataclass
class X509ConfigBasicConstraints:
    ca: bool = False
    path_length: int = 0
    critical: bool = False

    def to_obj(self):
        return x509.BasicConstraints(self.ca, self.path_length)

@dataclass
class X509ConfigSubjectAlternativeName:
    """X509 subject alternative name configuration."""
    ips: list[str] = None
    dns: list[str] = None
    emails: list[str] = None

    def to_obj(self):
        names = []
        for ip in self.ips:
            ip_address = ipaddress.ip_address(ip)
            names.append(IPAddress(ip_address))

        for dns in self.dns:
            names.append(DNSName(idna.encode(dns).decode()))

        for email in self.emails:
            names.append(RFC822Name(idna.encode(email).decode()))

        return x509.SubjectAlternativeName(names)

class X509ConfigAccessDescriptionLocationType(enum.Enum):
    URL = "URL"

@dataclass
class X509ConfigAccessDescription:
    """X509 authority info access description configuration."""
    access_method: str
    access_location_type: X509ConfigAccessDescriptionLocationType
    access_location: str

    def to_obj(self):
        if self.access_location_type == X509ConfigAccessDescriptionLocationType.URL:
            location = UniformResourceIdentifier(self.access_location)
        else:
            raise NotImplementedError(f"Location type {self.access_location_type} is not implemented.")

        if self.access_location.upper() == "CA_ISSUERS":
            return x509.AccessDescription(access_method=x509.OID_CA_ISSUERS, access_location=location)
        elif self.access_location.upper() == "OCSP":
            return x509.AccessDescription(access_method=x509.OID_OCSP, access_location=location)
        else:
            raise NotImplementedError(f"Location type {self.access_location_type} is not implemented.")


@dataclass
class X509ConfigAuthorityInfoAccess:
    """X509 authority info access configuration."""
    descriptions: list[X509ConfigAccessDescription]

    def to_obj(self):
        descriptions = [desc.to_obj() for desc in self.descriptions]
        return x509.AuthorityInformationAccess(descriptions)

@dataclass
class X509ConfigDistributionPoint:
    """X509 distribution point configuration."""
    names: list[str]
    reasons: list[str]

    def to_obj(self):
        reasons = frozenset([x509.ReasonFlags.__getitem__(reason) for reason in self.reasons])
        names = [x509.UniformResourceIdentifier(name) for name in self.names]
        return x509.DistributionPoint(names, relative_name=None, crl_issuer=None, reasons=reasons)


@dataclass
class X509ConfigCRLDistributionPoints:
    """X509 CRL distribution points configuration."""
    points: list[X509ConfigDistributionPoint]

    def to_obj(self):
        return x509.CRLDistributionPoints([point.to_obj() for point in self.points])

@dataclass
class X509Config:
    """X509 configuration."""
    subject_name: X509ConfigSubjectName
    basic_constraints: X509ConfigBasicConstraints
    key_usage: X509ConfigKeyUsage
    authority_info_access: X509ConfigAuthorityInfoAccess = None
    crl_distribution_points: X509ConfigCRLDistributionPoints = None
    extended_key_usage: X509ConfigExtendedKeyUsage = None
    subject_alternative_name: X509ConfigSubjectAlternativeName = None


@dataclass
class CertificateConfig:
    """Configuration for a certificate."""

    name: str

    signed_by: str = None
    externally_managed: bool = False
    certificate_pem: str = None
    crl_pem: str = None

    key: KeyConfig = None
    x509: X509Config = None

    @property
    def key_label(self):
        if self.key.algorithm == SupportedKeyAlgorithms.rsa:
            return f"{self.name}-{self.key.algorithm.value}-{self.key.bits}"
        if self.key.algorithm == SupportedKeyAlgorithms.ec:
            return f"{self.name}-{self.key.algorithm.value}-{self.key.curve}"
        else:
            raise ValueError(f"Unsupported key algorithm: {self.key.algorithm}")


    @property
    def key_p11_attributes(self):
        attributes: dict[pkcs11.Attribute, Any] = {
            pkcs11.Attribute.LABEL: self.key_label,
            pkcs11.Attribute.ID: hashlib.sha3_256(self.name.encode()).digest(),
        }

        if self.key.algorithm == SupportedKeyAlgorithms.rsa:
            attributes[pkcs11.Attribute.KEY_TYPE] = pkcs11.KeyType.RSA
            attributes[pkcs11.Attribute.MODULUS_BITS] = self.key.bits

        if self.key.algorithm == SupportedKeyAlgorithms.ec:
            attributes[pkcs11.Attribute.KEY_TYPE] = pkcs11.KeyType.EC
            attributes[pkcs11.Attribute.EC_PARAMS] = encode_named_curve_parameters(self.key.curve)

        return attributes


@dataclass
class CAConfig(VismConfig):
    """Main configuration class for Vism CA."""

    __path__: ClassVar[str] = "vism_ca"
    __config_dir__: ClassVar[str] = f"{os.getenv("CONFIG_DIR", os.getcwd()).rstrip("/")}"
    __config_file__: ClassVar[str] = f"{__config_dir__}/vism_ca.yaml"

    pkcs11: PKCS11Config = None
    x509_certificates: list[CertificateConfig] = None

    def get_cert_config_by_name(self, cert_name: str) -> CertificateConfig:
        """Get certificate configuration by name."""
        cert_configs = list(filter(lambda conf: conf.name == cert_name, self.x509_certificates))
        if not cert_configs:
            raise CertConfigNotFound(f"Certificate with name '{cert_name}' not found in config.")
        if len(cert_configs) > 1:
            raise ValueError(f"Multiple certificates found with the name: '{cert_name}'")

        return cert_configs[0]
