from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1_modules import rfc2986

from ca.abc import Key, KeyManager, PrivateKey, PublicKey
from ca.config import CertificateConfig, SupportedKeyAlgorithms


# =========================================================================
# Key-manager test doubles
# =========================================================================

class LocalPrivKey(PrivateKey, Key):
    """In-memory PrivateKey that satisfies the abc.PrivateKey protocol.
    Wraps a cryptography private key so LocalKeyManager can sign with it."""

    def __init__(self, crypto_key, label: str = "test-priv", key_id: bytes = b"test-id"):
        self._crypto_key = crypto_key
        self._label = label
        self._id = key_id

    @property
    def label(self) -> str:
        return self._label

    @property
    def id(self) -> bytes:
        return self._id

    @property
    def key_type(self):
        if isinstance(self._crypto_key, ec.EllipticCurvePrivateKey):
            return "EC"
        if isinstance(self._crypto_key, rsa.RSAPrivateKey):
            return "RSA"
        return "UNKNOWN"

    @property
    def key_length(self) -> int:
        if isinstance(self._crypto_key, rsa.RSAPrivateKey):
            return self._crypto_key.key_size
        return self._crypto_key.curve.key_size


class LocalPubKey(PublicKey, Key):
    """In-memory PublicKey that satisfies the abc.PublicKey protocol."""

    def __init__(self, crypto_key, label: str = "test-pub", key_id: bytes = b"test-id"):
        self._crypto_key = crypto_key
        self._label = label
        self._id = key_id

    @property
    def label(self) -> str:
        return self._label

    @property
    def id(self) -> bytes:
        return self._id

    @property
    def key_type(self):
        if isinstance(self._crypto_key, ec.EllipticCurvePublicKey):
            return "EC"
        if isinstance(self._crypto_key, rsa.RSAPublicKey):
            return "RSA"
        return "UNKNOWN"

    @property
    def key_length(self) -> int:
        if isinstance(self._crypto_key, rsa.RSAPublicKey):
            return self._crypto_key.key_size
        return self._crypto_key.curve.key_size

    def public_bytes(self) -> bytes:
        return self._crypto_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class LocalKeyManager(KeyManager[LocalPrivKey, LocalPubKey]):
    """In-memory KeyManager test double. Generates and stores cryptography
    EC private keys keyed by label, so make_key_descriptors() returns
    stable descriptors across calls (matching PKCS11Client's idempotent
    behavior).

    Signatures produced by sign_data_with_key match the format
    PKCS11Client produces (DER ECDSA for EC, raw PKCS#1 v1.5 for RSA), so
    consumers like CertificateManager don't care which backend they're
    talking to.
    """

    _HASHES = {"SHA256": hashes.SHA256, "SHA384": hashes.SHA384, "SHA512": hashes.SHA512}
    _CURVES = {
        "secp256r1": ec.SECP256R1,
        "secp384r1": ec.SECP384R1,
        "secp521r1": ec.SECP521R1,
    }

    def __init__(self):
        # Keyed by label so generate_or_load_keypair behaves idempotently —
        # the second call with the same label returns the same key.
        self._keys: dict[str, Any] = {}

    def sign_data_with_key(self, privkey: LocalPrivKey, data: bytes, hash_alg_name: str) -> bytes:
        hash_cls = self._HASHES[hash_alg_name]
        crypto_key = privkey._crypto_key
        if isinstance(crypto_key, ec.EllipticCurvePrivateKey):
            return crypto_key.sign(data, ec.ECDSA(hash_cls()))
        if isinstance(crypto_key, rsa.RSAPrivateKey):
            return crypto_key.sign(data, padding.PKCS1v15(), hash_cls())
        raise NotImplementedError(f"Unsupported key type: {type(crypto_key)}")

    def generate_or_load_keypair(
            self,
            pub_key: LocalPubKey,
            priv_key: LocalPrivKey,
    ) -> tuple[LocalPubKey, LocalPrivKey]:
        # If we've seen this label, reuse the stored key (idempotent
        # second call). Otherwise the key on priv_key is the one to keep.
        label = priv_key.label
        if label in self._keys:
            stored = self._keys[label]
            return (
                LocalPubKey(stored.public_key(), label=pub_key.label, key_id=pub_key.id),
                LocalPrivKey(stored, label=priv_key.label, key_id=priv_key.id),
            )
        self._keys[label] = priv_key._crypto_key
        return pub_key, priv_key

    def make_key_descriptors(self, cert: CertificateConfig) -> tuple[LocalPubKey, LocalPrivKey]:
        """Build descriptors for a fresh keypair from a CertificateConfig.
        Mirrors PKCS11Client.make_key_descriptors but constructs
        cryptography keys instead of PKCS#11 attribute bags."""
        if cert.key.algorithm == SupportedKeyAlgorithms.ec:
            curve_cls = self._CURVES.get(cert.key.curve, ec.SECP256R1)
            crypto_key = ec.generate_private_key(curve_cls())
        elif cert.key.algorithm == SupportedKeyAlgorithms.rsa:
            crypto_key = rsa.generate_private_key(
                public_exponent=65537, key_size=cert.key.bits or 2048,
            )
        else:
            raise NotImplementedError(f"Unsupported algorithm: {cert.key.algorithm}")

        label = cert.name
        key_id = label.encode()[:16].ljust(16, b"\x00")
        return (
            LocalPubKey(crypto_key.public_key(), label=f"{label}-pub", key_id=key_id),
            LocalPrivKey(crypto_key, label=f"{label}-priv", key_id=key_id),
        )


# =========================================================================
# External-service test doubles
# =========================================================================

@dataclass
class _S3Upload:
    """One recorded upload_bytes() call."""
    key: str
    data: bytes


class FakeS3Client:
    """Records uploads in memory so tests can assert what got pushed.
    Only implements the surface VismCA actually calls (create_bucket and
    upload_bytes). download_bytes/exists/list_files are not implemented."""

    def __init__(self):
        self.bucket_created = False
        self.uploads: list[_S3Upload] = []

    async def create_bucket(self):
        self.bucket_created = True

    async def upload_bytes(self, data: bytes, key: str, **_kwargs):
        self.uploads.append(_S3Upload(key=key, data=data))

    def uploaded_keys(self) -> list[str]:
        return [u.key for u in self.uploads]

    def get_upload(self, key: str) -> _S3Upload | None:
        for u in self.uploads:
            if u.key == key:
                return u
        return None


@dataclass
class _ReceiveSubscription:
    """One recorded receive_messages() registration. Tests can drive the
    callback manually via FakeDataExchange.dispatch()."""
    message_class: type
    callback: Callable[..., Coroutine[Any, Any, None]]


class FakeDataExchange:
    """Records send_message() calls and receive_messages() subscriptions.
    Doesn't actually run a message loop — tests dispatch messages by
    calling .dispatch() directly."""

    def __init__(self):
        self.sent: list[Any] = []
        self.subscriptions: list[_ReceiveSubscription] = []
        self.cleanup_calls: list[bool] = []

    async def send_message(self, message):
        self.sent.append(message)

    async def receive_messages(self, message_class, callback):
        self.subscriptions.append(_ReceiveSubscription(
            message_class=message_class, callback=callback,
        ))

    async def cleanup(self, full: bool = False):
        self.cleanup_calls.append(full)

    async def dispatch(self, message):
        """Hand the message to all matching subscribed callbacks.
        Mimics what a real broker would do on receipt."""
        for sub in self.subscriptions:
            if isinstance(message, sub.message_class):
                await sub.callback(message)


# =========================================================================
# CSR builder for tests that exercise the leaf-signing path
# =========================================================================

def make_external_leaf_csr(
    key: ec.EllipticCurvePrivateKey,
    cn: str,
    dns: list[str] | None = None,
) -> rfc2986.CertificationRequest:
    """Build a leaf CSR as an external client (e.g. ACME) would. Leaf
    CSRs come from outside and don't include issuer-side extensions like
    AIA/CRLDP; those are added by the issuing CA's sign_csr."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    )
    if dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in dns]),
            critical=False,
        )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    csr_der = builder.sign(key, hashes.SHA384()).public_bytes(serialization.Encoding.DER)
    return der_decoder(csr_der, asn1Spec=rfc2986.CertificationRequest())[0]
