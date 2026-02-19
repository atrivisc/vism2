from typing import Any

import pkcs11
from pkcs11 import Attribute, LocalDomainParameters


class PKCS11Object:
    LABEL_SUFFIX = ""
    OVERRIDES = {}
    BASE_TEMPLATE = {}

    def __init__(self, attributes: dict[Attribute, Any]):
        self.attributes = attributes

    @property
    def label(self) -> str:
        return self.attributes[pkcs11.Attribute.LABEL] + (f"-{self.LABEL_SUFFIX}" if self.LABEL_SUFFIX else "")

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