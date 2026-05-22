"""
Configuration module for Vism CA.

This module provides configuration classes for the CA, including database
configuration, certificate configuration, and the main CA configuration class.
"""
import abc
import enum
import hashlib
import logging
import os
from dataclasses import field
from typing import ClassVar, Any
import pkcs11
from cryptography import x509
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from pkcs11.util.ec import encode_named_curve_parameters
from pyasn1.type import univ, char, tag
from pyasn1_modules import rfc5280
from pydantic import field_validator
from pydantic.dataclasses import dataclass
from ca.errors import CertConfigNotFound
from vism_lib.config import VismConfig
from pyasn1.codec.der.encoder import encode as der_encoder

logger = logging.getLogger(__name__)
ca_logger = logging.getLogger("vism_ca")

class ValidRevocationReasons(enum.Enum):
    unspecified = "unspecified"
    keyCompromise = "keyCompromise"
    cACompromise = "cACompromise"
    affiliationChanged = "affiliationChanged"
    superseded = "superseded"
    cessationOfOperation = "cessationOfOperation"
    certificateHold = "certificateHold"
    removeFromCRL = "removeFromCRL"
    privilegeWithdrawn = "privilegeWithdrawn"
    aACompromise = "aACompromise"

class SupportedKeyAlgorithms(enum.Enum):
    """Supported key algorithms."""
    rsa = "RSA"
    ec = "EC"

@dataclass
class X509ConfigExtension(metaclass=abc.ABCMeta):
    """X509 base extension configuration."""
    OID: ClassVar[str]

    critical: bool = field(default=False)

    @abc.abstractmethod
    def to_asn1(self):
        raise NotImplementedError()

    def to_asn1_ext(self):
        extn = rfc5280.Extension()
        extn.setComponentByName("extnID", univ.ObjectIdentifier(self.OID))

        if self.critical:
            extn.setComponentByName("critical", univ.Boolean(True))

        extn.setComponentByName("extnValue", der_encoder(self.to_asn1()))
        return extn


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

@dataclass
class X509ConfigSubjectName:
    """X509 subject name configuration."""
    common_name: str = None
    country: str = None
    state_or_province: str = None
    locality: str = None
    organization: str = None

    @staticmethod
    def _add_rdn(rdn_seq: rfc5280.RDNSequence, attribute_type: ObjectIdentifier, value: str):
        if value:
            rdn = rfc5280.RelativeDistinguishedName()
            attr = rfc5280.AttributeTypeAndValue()
            attr.setComponentByName("type", univ.ObjectIdentifier(attribute_type.dotted_string))
            attr.setComponentByName("value", char.UTF8String(value))
            rdn.append(attr)
            rdn_seq.append(rdn)

    def to_rdn_seq(self):
        rdn_seq = rfc5280.RDNSequence()

        self._add_rdn(rdn_seq, x509.NameOID.COMMON_NAME, self.common_name)
        self._add_rdn(rdn_seq, x509.NameOID.COUNTRY_NAME, self.country)
        self._add_rdn(rdn_seq, x509.NameOID.STATE_OR_PROVINCE_NAME, self.state_or_province)
        self._add_rdn(rdn_seq, x509.NameOID.LOCALITY_NAME, self.locality)
        self._add_rdn(rdn_seq, x509.NameOID.ORGANIZATION_NAME, self.organization)

        return rdn_seq

    def to_asn1(self):
        name = rfc5280.Name()
        name.setComponentByName("rdnSequence", self.to_rdn_seq())
        return name

@dataclass
class X509ConfigKeyUsage(X509ConfigExtension):
    """X509 key usage configuration."""
    OID: ClassVar[str] = x509.OID_KEY_USAGE.dotted_string

    digital_signature: bool = False
    non_repudiation: bool = False
    key_encipherment: bool = False
    data_encipherment: bool = False
    key_agreement: bool = False
    key_cert_sign: bool = False
    crl_sign: bool = False
    encipher_only: bool = False
    decipher_only: bool = False

    def to_asn1(self):
        return rfc5280.KeyUsage(
            f"{int(self.digital_signature)}"
            f"{int(self.non_repudiation)}"
            f"{int(self.key_encipherment)}"
            f"{int(self.data_encipherment)}"
            f"{int(self.key_agreement)}"
            f"{int(self.key_cert_sign)}"
            f"{int(self.crl_sign)}"
            f"{int(self.encipher_only)}"
            f"{int(self.decipher_only)}"
        )


@dataclass
class X509ConfigExtendedKeyUsage(X509ConfigExtension):
    OID: ClassVar[str] = x509.OID_EXTENDED_KEY_USAGE.dotted_string
    usages: list[str] = field(default_factory=list)

    def to_asn1(self):
        extended_key_usage = rfc5280.ExtKeyUsageSyntax()

        for usage in self.usages:
            extended_key_usage.append(rfc5280.KeyPurposeId(usage))

        return extended_key_usage

@dataclass
class X509ConfigBasicConstraints(X509ConfigExtension):
    OID: ClassVar[str] = x509.OID_BASIC_CONSTRAINTS.dotted_string

    ca: bool = False
    path_length: int = 0

    def to_asn1(self):
        basic_constraints = rfc5280.BasicConstraints()
        basic_constraints.setComponentByName("cA", self.ca)
        if self.ca:
            basic_constraints.setComponentByName("pathLenConstraint", self.path_length)

        return basic_constraints


@dataclass
class X509ConfigSubjectAlternativeName(X509ConfigExtension):
    """X509 subject alternative name configuration."""
    OID: ClassVar[str] = x509.OID_SUBJECT_ALTERNATIVE_NAME.dotted_string

    ips: list[str] = None
    dns: list[str] = None
    emails: list[str] = None

    def to_asn1(self):
        import ipaddress as _ipaddress

        subject_alt_names = rfc5280.SubjectAltName()
        for ip in self.ips or []:
            packed = _ipaddress.ip_address(ip).packed
            name = rfc5280.GeneralName()
            name["iPAddress"] = univ.OctetString(packed).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
            )
            subject_alt_names.append(name)

        for dn in self.dns or []:
            name = rfc5280.GeneralName()
            name["dNSName"] = char.IA5String(dn).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )
            subject_alt_names.append(name)

        for email in self.emails or []:
            name = rfc5280.GeneralName()
            name["rfc822Name"] = char.IA5String(email).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
            subject_alt_names.append(name)

        return subject_alt_names

class X509ConfigAccessDescriptionMethod(enum.Enum):
    OCSP = "OCSP"
    CA = "CA"

class X509ConfigLocationType(enum.Enum):
    URL = "URL"

@dataclass
class X509ConfigAccessDescription:
    """X509 authority info access description configuration."""
    access_method: X509ConfigAccessDescriptionMethod = None
    access_location: str = None
    access_location_type: X509ConfigLocationType = X509ConfigLocationType.URL

    def to_ans1(self):
        access_description = rfc5280.AccessDescription()
        access_method = univ.ObjectIdentifier(
            x509.OID_OCSP.dotted_string if self.access_method == X509ConfigAccessDescriptionMethod.OCSP else x509.OID_CA_ISSUERS.dotted_string
        )
        access_location = rfc5280.GeneralName()
        if self.access_location_type == X509ConfigLocationType.URL:
            access_location["uniformResourceIdentifier"] = char.IA5String(self.access_location).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
        else:
            raise NotImplementedError(f"Location type {self.access_location_type} is not implemented.")

        access_description["accessMethod"] = access_method
        access_description["accessLocation"] = access_location
        return access_description


@dataclass
class X509ConfigAuthorityInfoAccess(X509ConfigExtension):
    """X509 authority info access configuration."""
    OID: ClassVar[str] = x509.OID_AUTHORITY_INFORMATION_ACCESS.dotted_string

    descriptions: list[X509ConfigAccessDescription] = field(default_factory=list)

    def to_asn1(self):
        authority_info_access = rfc5280.AuthorityInfoAccessSyntax()

        for description in self.descriptions:
            authority_info_access.append(description.to_ans1())

        return authority_info_access


class X509ConfigDistributionPointReasonFlags(enum.Enum):
    unused = "unused"
    keyCompromise = "keyCompromise"
    cACompromise = "cACompromise"
    affiliationChanged = "affiliationChanged"
    superseded = "superseded"
    cessationOfOperation = "cessationOfOperation"
    certificateHold = "certificateHold"
    privilegeWithdrawn = "privilegeWithdrawn"
    aACompromise = "aACompromise"

@dataclass
class X509ConfigDistributionPointName:
    """X509 distribution point name configuration."""
    name: str
    name_type: X509ConfigLocationType = X509ConfigLocationType.URL

    def to_general_name(self) -> rfc5280.GeneralName:
        general_name = rfc5280.GeneralName()
        if self.name_type == X509ConfigLocationType.URL:
            general_name["uniformResourceIdentifier"] = char.IA5String(self.name).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))
        else:
            raise NotImplementedError(f"Location type {self.name_type} is not implemented.")

        return general_name

@dataclass
class X509ConfigDistributionPoint:
    """X509 distribution point configuration."""
    names: list[X509ConfigDistributionPointName] = field(default_factory=list)
    reasons: list[X509ConfigDistributionPointReasonFlags] = field(default_factory=list)

    def to_asn1(self):
        dp = rfc5280.DistributionPoint()

        dp_name = rfc5280.DistributionPointName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        names = rfc5280.GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

        for name in self.names:
            names.append(name.to_general_name())

        dp_name["fullName"] = names
        dp["distributionPoint"] = dp_name

        if self.reasons:
            reasons = rfc5280.ReasonFlags(
                "".join(str(int(reason in self.reasons)) for reason in X509ConfigDistributionPointReasonFlags)
            ).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
            dp["reasons"] = reasons

        return dp


@dataclass
class X509ConfigCRLDistributionPoints(X509ConfigExtension):
    """X509 CRL distribution points configuration."""
    OID: ClassVar[str] = x509.OID_CRL_DISTRIBUTION_POINTS.dotted_string

    points: list[X509ConfigDistributionPoint] = field(default_factory=list)

    def to_asn1(self):
        crl_distribution_points = rfc5280.CRLDistributionPoints()

        for point in self.points:
            crl_distribution_points.append(point.to_asn1())

        return crl_distribution_points


@dataclass
class X509Config:
    """X509 configuration."""
    days: int
    crl_days: int

    subject_name: X509ConfigSubjectName
    basic_constraints: X509ConfigBasicConstraints
    key_usage: X509ConfigKeyUsage = None
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
