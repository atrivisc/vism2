from typing import Any

import pkcs11
from pkcs11 import Attribute, LocalDomainParameters


class PKCS11Object:

    def __init__(self, attributes: dict[Attribute, Any]):
        self.attributes = attributes

    @property
    def label(self) -> str:
        return self.attributes[pkcs11.Attribute.LABEL]

    @property
    def key_type(self) -> pkcs11.KeyType:
        return self.attributes[pkcs11.Attribute.KEY_TYPE]

    @property
    def key_length(self) -> int:
        return self.attributes[pkcs11.Attribute.MODULUS_BITS]

    @property
    def ec_params(self) -> LocalDomainParameters:
        return self.attributes[pkcs11.Attribute.EC_PARAMS]
