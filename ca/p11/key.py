import pkcs11
from pkcs11 import Attribute

from ca.p11.object import PKCS11Object


def _build_template(
        base_template: dict[Attribute, object],
        key_type: pkcs11.KeyType,
        label: str,
        overrides_by_type: dict[pkcs11.KeyType, dict[Attribute, object]],
) -> dict[Attribute, object]:
    overrides = overrides_by_type.get(key_type, {})
    return base_template | overrides | {Attribute.LABEL: label}


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
