import pkcs11

from pkcs11.util.ec import encode_named_curve_parameters
from ca.config import SupportedKeyAlgorithms
from ca.crypto.certificate import CryptoCertificate
from pkcs11 import Attribute, KeyType


class Crypto:

