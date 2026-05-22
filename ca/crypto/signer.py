import pkcs11
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ca.abc import Signer
from ca.p11 import PKCS11Client, PKCS11PrivKey


class PKCS11Signer(Signer):
    def __init__(self, p11_client: PKCS11Client, privkey: PKCS11PrivKey):
        self._p11_client = p11_client
        self._privkey = privkey

    def sign(self, data: bytes, hash_algorithm: str) -> bytes:
        signature_bytes = self._p11_client.sign_data(self._privkey, data, hash_algorithm)

        # p11 returns a raw signature for EC, so we need to encode it
        if self._privkey.key_type == pkcs11.KeyType.EC:
            sig_len = len(signature_bytes)
            int1 = signature_bytes[:(sig_len // 2)]
            int2 = signature_bytes[(sig_len // 2):]
            signature_bytes = encode_dss_signature(int.from_bytes(int1), int.from_bytes(int2))

        return signature_bytes