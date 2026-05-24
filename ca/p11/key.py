from typing import Any

import pkcs11
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import get_curve_for_oid
from pkcs11 import Attribute, LocalDomainParameters
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.type import univ
from cryptography.hazmat._oid import ObjectIdentifier

from ca.abc import Key, PublicKey, PrivateKey


class PKCS11Key(Key):
    LABEL_SUFFIX = ""
    OVERRIDES = {}
    BASE_TEMPLATE = {}

    def __init__(self, attributes: dict[Attribute, Any] = None):
        if attributes is None:
            attributes = {}

        self.attributes = attributes

    @property
    def label(self) -> str:
        label = self.attributes[pkcs11.Attribute.LABEL]
        if self.LABEL_SUFFIX and not label.endswith(self.LABEL_SUFFIX):
            label += f'-{self.LABEL_SUFFIX}'
        return label

    @property
    def id(self) -> str:
        return self.attributes[pkcs11.Attribute.ID]

    @property
    def key_type(self) -> pkcs11.KeyType:
        return self.attributes[pkcs11.Attribute.KEY_TYPE]

    @property
    def key_length(self) -> int:
        return self.attributes[pkcs11.Attribute.MODULUS_BITS]

    @property
    def ec_params(self) -> LocalDomainParameters:
        return self.attributes[pkcs11.Attribute.EC_PARAMS]

    @property
    def template(self) -> dict[pkcs11.Attribute, Any]:
        overrides = self.OVERRIDES.get(self.attributes[pkcs11.Attribute.KEY_TYPE], {})
        template = {
            pkcs11.Attribute.LABEL: self.label,
            pkcs11.Attribute.ID: self.id,
        }
        return self.BASE_TEMPLATE | overrides | template


class PKCS11PubKey(PublicKey, PKCS11Key):
    BASE_TEMPLATE = {
        Attribute.TOKEN: True,
        Attribute.PRIVATE: False,
        Attribute.VERIFY: True,
        Attribute.WRAP: False,
        Attribute.MODIFIABLE: False,
    }
    LABEL_SUFFIX = "public"
    OVERRIDES: dict[pkcs11.KeyType, dict[Attribute, object]] = {
        pkcs11.KeyType.RSA: {Attribute.ENCRYPT: True},
    }

    def __init__(self, attributes: dict[Attribute, Any], ec_curve: str = None):
        super().__init__(attributes)
        self.ec_curve = ec_curve

    def public_bytes(self) -> bytes:
        if self.key_type == pkcs11.KeyType.RSA:
            public_numbers = rsa.RSAPublicNumbers(
                int.from_bytes(self.attributes[pkcs11.Attribute.PUBLIC_EXPONENT], 'big'),
                int.from_bytes(self.attributes[pkcs11.Attribute.MODULUS], 'big')
            )
            rsa_pubkey = public_numbers.public_key()
            der_bytes = rsa_pubkey.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

        elif self.key_type == pkcs11.KeyType.EC:
            ec_point_der = self.attributes[pkcs11.Attribute.EC_POINT]
            ec_point = bytes(der_decoder(ec_point_der, asn1Spec=univ.OctetString())[0])

            curve_oid_str = str(der_decoder(self.attributes[pkcs11.Attribute.EC_PARAMS], asn1Spec=univ.ObjectIdentifier())[0])
            curve_oid = ObjectIdentifier(curve_oid_str)

            coord_len = (len(ec_point) - 1) // 2
            x_bytes = ec_point[1:1 + coord_len]
            y_bytes = ec_point[1 + coord_len:]

            x = int.from_bytes(x_bytes, byteorder="big")
            y = int.from_bytes(y_bytes, byteorder="big")

            curve = get_curve_for_oid(curve_oid)
            public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve())
            ec_pubkey = public_numbers.public_key()

            der_bytes = ec_pubkey.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        else:
            raise ValueError(f"Unsupported key type: {self.key_type}")

        return der_bytes


class PKCS11PrivKey(PrivateKey, PKCS11Key):
    BASE_TEMPLATE = {
        Attribute.PRIVATE: True,
        Attribute.TOKEN: True,
        Attribute.SIGN: True,
        Attribute.UNWRAP: False,
        Attribute.EXTRACTABLE: False,
        Attribute.MODIFIABLE: False,
        Attribute.SENSITIVE: True,
    }
    LABEL_SUFFIX = "private"
    OVERRIDES: dict[pkcs11.KeyType, dict[Attribute, object]] = {
        pkcs11.KeyType.RSA: {Attribute.DECRYPT: True},
    }
