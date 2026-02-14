"""
Configuration module for Vism CA.

This module provides configuration classes for the CA, including database
configuration, certificate configuration, and the main CA configuration class.
"""
import enum
import logging
import os
from typing import ClassVar, Any

import pkcs11
from pkcs11.util.ec import encode_named_curve_parameters
from pydantic import field_validator
from pydantic.dataclasses import dataclass
from ca.errors import CertConfigNotFound
from ca.p11 import PKCS11PrivKey, PKCS11PubKey
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
class CertificateConfig:
    """Configuration for a certificate."""

    name: str

    signed_by: str = None
    externally_managed: bool = False
    certificate_pem: str = None
    crl_pem: str = None

    key: KeyConfig = None
    crypto: CertificateCryptoConfig = None

    @property
    def label(self):
        if self.key.algorithm == SupportedKeyAlgorithms.rsa:
            return f"{self.name}-{self.key.algorithm.value}-{self.key.bits}"
        if self.key.algorithm == SupportedKeyAlgorithms.ec:
            return f"{self.name}-{self.key.algorithm.value}-{self.key.curve}"
        else:
            raise ValueError(f"Unsupported key algorithm: {self.key.algorithm}")

    @property
    def p11_attributes(self):
        attributes: dict[pkcs11.Attribute, Any] = {
            pkcs11.Attribute.LABEL: self.label,
        }

        if self.key.algorithm == SupportedKeyAlgorithms.rsa:
            attributes[pkcs11.Attribute.KEY_TYPE] = pkcs11.KeyType.RSA
            attributes[pkcs11.Attribute.MODULUS_BITS] = self.key.bits

        if self.key.algorithm == SupportedKeyAlgorithms.ec:
            attributes[pkcs11.Attribute.KEY_TYPE] = pkcs11.KeyType.EC
            attributes[pkcs11.Attribute.EC_PARAMS] = encode_named_curve_parameters(self.key.curve)

        return attributes

    @property
    def p11_pub_key(self):
        return PKCS11PubKey(self.p11_attributes)

    @property
    def p11_priv_key(self):
        return PKCS11PrivKey(self.p11_attributes)


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
