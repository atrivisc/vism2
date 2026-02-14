import hashlib
from dataclasses import field

import pkcs11

from typing import Self
from pkcs11.types import Token
from pkcs11._pkcs11 import lib
from pydantic.dataclasses import dataclass
from ca.database import CertificateEntity
from ca.config import CertificateConfig, SupportedKeyAlgorithms
from pkcs11.util.ec import encode_named_curve_parameters
from pkcs11 import Attribute, KeyType


@dataclass
class CryptoCertificate:
    """Data class for crypto data."""

    crt_pem: str = None
    key_pem: str = None
    pub_key_pem: str = None
    csr_pem: str = None
    crl_pem: str = None
    config: 'CertificateConfig' = None

    p11: lib = field(init=False, default=pkcs11.lib(config.pkcs11.lib_path))
    p11_token: Token = field(init=False, default=p11.get_token(config.pkcs11.token))

    @property
    def _label(self):
        if self.config.key.algorithm == SupportedKeyAlgorithms.ec:
            return f"{self.config.name}-{self.config.key.algorithm}-{self.config.key.curve}"
        elif self.config.key.algorithm == SupportedKeyAlgorithms.rsa:
            return f"{self.config.name}-{self.config.key.algorithm}-{self.config.key.bits}"
        else:
            raise ValueError(f"Unsupported key algorithm: {self.config.key.algorithm}")

    @property
    def _private_key_properties(self):
        return {
            Attribute.PRIVATE: True,
            Attribute.TOKEN: True,
            Attribute.SIGN: True,
            Attribute.DECRYPT: True,
            Attribute.UNWRAP: False,
            Attribute.EXTRACTABLE: False,
            Attribute.MODIFIABLE: False,
            Attribute.SENSITIVE: True,
            Attribute.ID: hashlib.sha256(f"{self._label}-private".encode()).digest(),
            Attribute.LABEL: f"{self._label}-private",
        }

    @property
    def _public_key_properties(self):
        return {
            Attribute.TOKEN: True,
            Attribute.PRIVATE: False,
            Attribute.VERIFY: True,
            Attribute.ENCRYPT: True,
            Attribute.WRAP: False,
            Attribute.EXTRACTABLE: True,
            Attribute.ID: hashlib.sha256(f"{self._label}-public".encode()).digest(),
            Attribute.LABEL: f"{self._label}-public"
        }

    def to_cert_entity(self):
        """Populate data from CryptoCert."""
        return CertificateEntity(
            name=self.config.name,
            crt_pem=self.crt_pem,
            csr_pem=self.csr_pem,
            pkey_pem=self.key_pem,
            pubkey_pem=self.pub_key_pem,
            crl_pem=self.crl_pem,
            externally_managed=self.config.externally_managed,
        )

    @classmethod
    def from_cert_entity(cls, cert_entity: CertificateEntity) -> Self:
        """Populate data from CertificateEntity."""
        return cls(
            crt_pem=cert_entity.crt_pem,
            key_pem=cert_entity.pkey_pem,
            pub_key_pem=cert_entity.pubkey_pem,
            csr_pem=cert_entity.csr_pem,
            crl_pem=cert_entity.crl_pem,
        )

    def generate_private_key_pair(self):
        with self.p11_token.open(user_pin=self.config.pkcs11.user_pin.encode("utf-8")) as session:
            if self.config.key.algorithm == SupportedKeyAlgorithms.rsa:
                self.key_pem, self.pub_key_pem = session.generate_keypair(
                    pkcs11.KeyType.RSA, self.config.key.bits,
                    private_template=self._private_key_properties,
                    public_template=self._public_key_properties,
                    store=True
                )
            elif self.config.key.algorithm == SupportedKeyAlgorithms.ec:
                ecc_params = session.create_domain_parameters(
                    key_type=KeyType.EC,
                    attrs={Attribute.EC_PARAMS: encode_named_curve_parameters(self.config.key.curve)}
                )
                self.key_pem, self.pub_key_pem = ecc_params.generate_keypair(
                    private_template=self._private_key_properties,
                    public_template=self._public_key_properties,
                    store=True
                )
            else:
                raise ValueError(f"Unsupported key algorithm: {self.config.key.algorithm}")

        return self
