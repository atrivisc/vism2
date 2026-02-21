import hashlib
from typing import Any

import pkcs11
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import get_curve_for_oid
from pkcs11 import Attribute
from ca.p11.object import PKCS11Object
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.type import univ, useful, tag, char
from cryptography.hazmat._oid import ObjectIdentifier

class PKCS11PubKey(PKCS11Object):
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


class PKCS11PrivKey(PKCS11Object):
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
