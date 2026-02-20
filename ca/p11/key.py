import hashlib

import pkcs11
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from pkcs11 import Attribute
from ca.p11.object import PKCS11Object


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
        pkcs11.KeyType.EC: {Attribute.VERIFY: False},
        pkcs11.KeyType.RSA: {Attribute.ENCRYPT: True},
    }

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
            ec_point = self.attributes[pkcs11.Attribute.EC_POINT]

            if ec_point[0] == 0x04:
                ec_point = ec_point[1:]

            curve = ec.SECP256R1()
            ec_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(curve, ec_point)

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
        pkcs11.KeyType.EC: {Attribute.ENCRYPT: False},
        pkcs11.KeyType.RSA: {Attribute.DECRYPT: True},
    }
