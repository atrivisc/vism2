from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import subprocess
import textwrap
import uuid
from pathlib import Path

import pkcs11
import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from pkcs11.util.ec import encode_named_curve_parameters

from ca.certificate import CertificateManager
from ca.config import (
    CertificateConfig,
    KeyConfig,
    SupportedKeyAlgorithms,
    X509Config,
    X509ConfigAuthorityInfoAccess,
    X509ConfigAccessDescription,
    X509ConfigAccessDescriptionMethod,
    X509ConfigBasicConstraints,
    X509ConfigCRLDistributionPoints,
    X509ConfigDistributionPoint,
    X509ConfigDistributionPointName,
    X509ConfigKeyUsage,
    X509ConfigSubjectName,
)
from ca.crypto.signer import PKCS11Signer
from ca.p11 import PKCS11Client
from ca.p11.key import PKCS11PrivKey, PKCS11PubKey


pytestmark = pytest.mark.integration

SOFTHSM_TOKEN_LABEL = "vism-ca-test"
SOFTHSM_USER_PIN = "1234"
SOFTHSM_SO_PIN = "5678"


@pytest.fixture
def requires_ec(p11_supports_ec):
    """Skip the test if the underlying PKCS#11 token doesn't expose EC
    mechanisms. Apply by adding `requires_ec` to a test's argument list."""
    if not p11_supports_ec:
        pytest.skip("PKCS#11 token does not expose EC mechanisms (likely SoftHSM built without --enable-ecc)")


# =========================================================================
# Helpers
# =========================================================================

def _unique_label(prefix: str) -> str:
    """Each test uses a fresh label so SoftHSM tokens don't pollute
    across tests."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _ec_keypair_objects(label: str, curve: str = "secp256r1") -> tuple[PKCS11PubKey, PKCS11PrivKey]:
    """Build the in-memory descriptors that PKCS11Client uses to
    generate or look up an EC keypair."""
    key_id = hashlib.sha3_256(label.encode()).digest()
    common_attrs = {
        pkcs11.Attribute.LABEL: label,
        pkcs11.Attribute.ID: key_id,
        pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC,
        pkcs11.Attribute.EC_PARAMS: encode_named_curve_parameters(curve),
    }
    pub = PKCS11PubKey(attributes=dict(common_attrs), ec_curve=curve)
    priv = PKCS11PrivKey(attributes=dict(common_attrs))
    return pub, priv


def _rsa_keypair_objects(label: str, bits: int = 2048) -> tuple[PKCS11PubKey, PKCS11PrivKey]:
    key_id = hashlib.sha3_256(label.encode()).digest()
    common_attrs = {
        pkcs11.Attribute.LABEL: label,
        pkcs11.Attribute.ID: key_id,
        pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
        pkcs11.Attribute.MODULUS_BITS: bits,
    }
    pub = PKCS11PubKey(attributes=dict(common_attrs))
    priv = PKCS11PrivKey(attributes=dict(common_attrs))
    return pub, priv


def _find_softhsm_lib() -> str:
    """Locate libsofthsm2 across the common install paths. Override via
    SOFTHSM_LIB_PATH env var."""
    explicit = os.environ.get("SOFTHSM_LIB_PATH")
    if explicit:
        return explicit

    candidates = [
        "/usr/lib/softhsm/libsofthsm2.so",  # Debian/Ubuntu
        "/usr/lib64/softhsm/libsofthsm2.so",  # Fedora/RHEL
        "/usr/lib64/libsofthsm2.so",  # RHEL
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    raise RuntimeError("Could not find libsofthsm2.so.")


def _find_softhsm_util() -> str:
    util = shutil.which("softhsm2-util")
    if not util:
        raise RuntimeError("softhsm2-util not on PATH. Is SoftHSM installed?")
    return util


@pytest.fixture(scope="session")
def softhsm_lib_path() -> str:
    return _find_softhsm_lib()


@pytest.fixture(scope="session")
def softhsm_token_dir(tmp_path_factory) -> Path:
    """Create a hermetic SoftHSM token directory for this test session.
    Writes a softhsm2.conf pointing at it and sets SOFTHSM2_CONF so
    libsofthsm2 sees only this token store."""
    base = tmp_path_factory.mktemp("softhsm")
    tokens_dir = base / "tokens"
    tokens_dir.mkdir()
    conf_path = base / "softhsm2.conf"
    conf_path.write_text(textwrap.dedent(f"""\
        directories.tokendir = {tokens_dir}
        objectstore.backend = file
        log.level = ERROR
        slots.removable = false
    """))
    # SOFTHSM2_CONF must be set BEFORE pkcs11.lib() is first called,
    # because libsofthsm2 reads it on load.
    os.environ["SOFTHSM2_CONF"] = str(conf_path)
    return base


@pytest.fixture(scope="session")
def softhsm_token(softhsm_token_dir) -> str:
    """Initialize a token in the hermetic SoftHSM directory. Returns
    the token label."""
    util = _find_softhsm_util()
    # Initialize the first free slot with our token label.
    result = subprocess.run(
        [
            util, "--init-token", "--free",
            "--label", SOFTHSM_TOKEN_LABEL,
            "--pin", SOFTHSM_USER_PIN,
            "--so-pin", SOFTHSM_SO_PIN,
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"softhsm2-util --init-token failed (rc={result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return SOFTHSM_TOKEN_LABEL


@pytest.fixture(scope="session")
def p11_config(softhsm_lib_path, softhsm_token):
    """A PKCS11Config wired up to the hermetic SoftHSM session."""
    from ca.config import PKCS11Config
    return PKCS11Config(
        lib_path=softhsm_lib_path,
        token_label=softhsm_token,
        user_pin=SOFTHSM_USER_PIN,
    )


@pytest.fixture(scope="session")
def p11_client(p11_config):
    """A single PKCS11Client shared across the session. pkcs11.lib()
    caches the library handle globally so it's fine — and cheaper than
    reconnecting per test."""
    from ca.p11 import PKCS11Client
    return PKCS11Client(p11_config)


@pytest.fixture(scope="session")
def p11_supports_ec(p11_client) -> bool:
    """Whether the PKCS#11 token supports any form of ECDSA signing.
    PKCS11Client._get_mechanism uses the combined ECDSA_SHA* mechanism
    when available and falls back to bare CKM_ECDSA otherwise, so we
    accept either."""
    import pkcs11 as _pkcs11
    return (
            _pkcs11.Mechanism.ECDSA_SHA384 in p11_client.supported_mechanisms
            or _pkcs11.Mechanism.ECDSA in p11_client.supported_mechanisms
    )


# =========================================================================
# PKCS11Client basic mechanics
# =========================================================================

class TestPKCS11Client:

    def test_client_connects_to_token(self, p11_client):
        """The client successfully opens the token and reads its
        mechanisms. If this fails, every other test will too — making
        it the first thing to check on a broken setup."""
        assert p11_client.token is not None
        assert len(p11_client.supported_mechanisms) > 0

    def test_supported_mechanisms_include_ecdsa(self, p11_client, p11_supports_ec):
        """The CA needs *some* form of ECDSA signing. _get_mechanism
        prefers the combined ECDSA_SHA* mechanism when available and
        falls back to bare ECDSA (with caller-side hashing) otherwise.
        Either is fine for our purposes."""
        if not p11_supports_ec:
            pytest.skip("PKCS#11 token does not expose any ECDSA mechanism")
        has_combined = pkcs11.Mechanism.ECDSA_SHA384 in p11_client.supported_mechanisms
        has_bare = pkcs11.Mechanism.ECDSA in p11_client.supported_mechanisms
        assert has_combined or has_bare

    def test_supported_mechanisms_include_rsa(self, p11_client):
        assert pkcs11.Mechanism.SHA384_RSA_PKCS in p11_client.supported_mechanisms


# =========================================================================
# Key generation
# =========================================================================

class TestEcKeyGeneration:

    def test_generates_new_ec_keypair(self, p11_client):
        pub_desc, priv_desc = _ec_keypair_objects(_unique_label("test-ec-gen"))
        loaded_pub, loaded_priv = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        assert isinstance(loaded_pub, PKCS11PubKey)
        assert isinstance(loaded_priv, PKCS11PrivKey)
        assert loaded_priv.key_type == pkcs11.KeyType.EC

    def test_load_idempotent_for_existing_key(self, p11_client):
        """Calling generate_or_load_keypair twice with the same label
        should return the same key, not generate a new one."""
        label = _unique_label("test-ec-idem")
        pub_desc, priv_desc = _ec_keypair_objects(label)
        _, priv_a = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        _, priv_b = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        # Same key ID across both calls
        assert priv_a.id == priv_b.id

    def test_loaded_pubkey_has_ec_point(self, p11_client):
        pub_desc, priv_desc = _ec_keypair_objects(_unique_label("test-ec-point"))
        loaded_pub, _ = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        assert pkcs11.Attribute.EC_POINT in loaded_pub.attributes
        assert pkcs11.Attribute.EC_PARAMS in loaded_pub.attributes


class TestRsaKeyGeneration:

    def test_generates_new_rsa_keypair(self, p11_client):
        pub_desc, priv_desc = _rsa_keypair_objects(_unique_label("test-rsa-gen"))
        loaded_pub, loaded_priv = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        assert loaded_priv.key_type == pkcs11.KeyType.RSA

    def test_loaded_pubkey_has_modulus_and_exponent(self, p11_client):
        pub_desc, priv_desc = _rsa_keypair_objects(_unique_label("test-rsa-mod"))
        loaded_pub, _ = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        assert pkcs11.Attribute.MODULUS in loaded_pub.attributes
        assert pkcs11.Attribute.PUBLIC_EXPONENT in loaded_pub.attributes


# =========================================================================
# Public-key serialization (PKCS11PubKey.public_bytes)
# =========================================================================

class TestPublicKeySerialization:

    def test_ec_public_bytes_loadable_by_cryptography(self, p11_client):
        pub_desc, priv_desc = _ec_keypair_objects(_unique_label("test-ec-spki"))
        loaded_pub, _ = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        spki_der = loaded_pub.public_bytes()
        loaded_key = serialization.load_der_public_key(spki_der)
        assert isinstance(loaded_key, ec.EllipticCurvePublicKey)
        assert loaded_key.curve.name == "secp256r1"

    def test_ec_public_bytes_is_valid_spki(self, p11_client):
        """The output must be a valid SubjectPublicKeyInfo, not just
        the raw EC point. CertificateManager.__init__ calls
        load_der_public_key on these bytes."""
        pub_desc, priv_desc = _ec_keypair_objects(_unique_label("test-ec-fmt"))
        loaded_pub, _ = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        spki_der = loaded_pub.public_bytes()
        # SPKI DER starts with a SEQUENCE tag (0x30); a raw EC point would not.
        assert spki_der[0] == 0x30

    def test_rsa_public_bytes_loadable_by_cryptography(self, p11_client):
        pub_desc, priv_desc = _rsa_keypair_objects(_unique_label("test-rsa-spki"))
        loaded_pub, _ = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        spki_der = loaded_pub.public_bytes()
        loaded_key = serialization.load_der_public_key(spki_der)
        assert isinstance(loaded_key, rsa.RSAPublicKey)
        assert loaded_key.key_size == 2048


# =========================================================================
# Signing round-trips
# =========================================================================

class TestPKCS11ClientSigning:
    """Test the low-level sign_data interface — bytes in, raw signature
    out. The PKCS11Signer wrapper handles algorithm-specific formatting
    on top of this."""

    def test_ec_sign_returns_bytes(self, p11_client, requires_ec):
        pub_desc, priv_desc = _ec_keypair_objects(_unique_label("test-ec-sign"))
        loaded_pub, loaded_priv = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        sig = p11_client.sign_data_with_key(loaded_priv, b"hello world", "SHA384")
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_ec_sign_returns_raw_concat_format(self, p11_client, requires_ec):
        """PKCS#11 returns ECDSA signatures as r||s concatenation (NOT
        DER-encoded). For P-256, that's exactly 64 bytes (32 + 32).
        PKCS11Signer converts this to DER before passing it up."""
        pub_desc, priv_desc = _ec_keypair_objects(_unique_label("test-ec-rawsig"))
        loaded_pub, loaded_priv = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        sig = p11_client.sign_data_with_key(loaded_priv, b"hello world", "SHA384")
        # P-256: 32-byte r + 32-byte s
        assert len(sig) == 64


class TestPKCS11Signer:
    """PKCS11Signer wraps PKCS11Client.sign_data and converts the raw
    r||s output to a DER-encoded ECDSA signature, which is what
    cryptography.x509.Certificate expects."""

    @pytest.mark.parametrize("hash_alg", ["SHA256", "SHA384", "SHA512"])
    def test_ec_signature_verifies_via_cryptography(self, p11_client, requires_ec, hash_alg):
        pub_desc, priv_desc = _ec_keypair_objects(_unique_label(f"test-ec-verify-{hash_alg}"))
        loaded_pub, loaded_priv = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        signer = PKCS11Signer(p11_client, loaded_priv)
        data = b"the quick brown fox jumps over the lazy dog"
        signature = signer.sign(data, hash_alg)

        # Reconstitute the public key and verify the signature.
        pub_crypto = serialization.load_der_public_key(loaded_pub.public_bytes())
        hash_cls = {"SHA256": hashes.SHA256, "SHA384": hashes.SHA384, "SHA512": hashes.SHA512}[hash_alg]
        pub_crypto.verify(signature, data, ec.ECDSA(hash_cls()))

    def test_ec_signature_fails_verification_on_tampered_data(self, p11_client, requires_ec):
        """Negative test: a signature over message A should NOT verify
        as a signature over message B. This catches the case where the
        signer might accidentally produce a fixed/empty signature."""
        pub_desc, priv_desc = _ec_keypair_objects(_unique_label("test-ec-tamper"))
        loaded_pub, loaded_priv = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        signer = PKCS11Signer(p11_client, loaded_priv)
        signature = signer.sign(b"original message", "SHA384")

        pub_crypto = serialization.load_der_public_key(loaded_pub.public_bytes())
        with pytest.raises(InvalidSignature):
            pub_crypto.verify(signature, b"tampered message", ec.ECDSA(hashes.SHA384()))

    def test_rsa_signature_verifies_via_cryptography(self, p11_client):
        pub_desc, priv_desc = _rsa_keypair_objects(_unique_label("test-rsa-verify"))
        loaded_pub, loaded_priv = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
        signer = PKCS11Signer(p11_client, loaded_priv)
        data = b"the quick brown fox jumps over the lazy dog"
        signature = signer.sign(data, "SHA384")

        pub_crypto = serialization.load_der_public_key(loaded_pub.public_bytes())
        pub_crypto.verify(signature, data, padding.PKCS1v15(), hashes.SHA384())


# =========================================================================
# Full chain backed by SoftHSM
# =========================================================================

def _ca_x509_config(cn: str, *, path_length: int = 0, aia_url: str | None = None, crl_url: str | None = None) -> X509Config:
    kwargs = dict(
        days=3650, crl_days=7,
        subject_name=X509ConfigSubjectName(common_name=cn, country="EE"),
        basic_constraints=X509ConfigBasicConstraints(ca=True, path_length=path_length, critical=True),
        key_usage=X509ConfigKeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=True, critical=True),
    )
    if aia_url:
        kwargs["authority_info_access"] = X509ConfigAuthorityInfoAccess(
            descriptions=[X509ConfigAccessDescription(
                access_method=X509ConfigAccessDescriptionMethod.OCSP,
                access_location=aia_url,
            )]
        )
    if crl_url:
        kwargs["crl_distribution_points"] = X509ConfigCRLDistributionPoints(
            points=[X509ConfigDistributionPoint(
                names=[X509ConfigDistributionPointName(name=crl_url)],
            )]
        )
    return X509Config(**kwargs)


def _make_manager_with_hsm(name: str, x509_cfg: X509Config, p11_client) -> CertificateManager:
    """Build a CertificateManager whose Signer is backed by a fresh
    SoftHSM keypair."""
    label = _unique_label(f"chain-{name}")
    pub_desc, priv_desc = _ec_keypair_objects(label)
    loaded_pub, loaded_priv = p11_client.generate_or_load_keypair(pub_desc, priv_desc)
    return CertificateManager(
        signer=PKCS11Signer(p11_client, loaded_priv),
        config=CertificateConfig(
            name=name,
            key=KeyConfig(algorithm=SupportedKeyAlgorithms.ec, curve="secp256r1"),
            x509=x509_cfg,
        ),
        public_key_bytes=loaded_pub.public_bytes(),
    )


class TestHsmBackedChainIssuance:
    """The big one: build a complete root -> intermediate -> leaf chain
    where every signature was produced by SoftHSM. Verify each link
    cryptographically. This is the test that confirms the entire stack
    — config layer, certificate builder, PKCS11Signer, PKCS11Client —
    works together against a real HSM."""

    def test_full_chain_verifies(self, p11_client, requires_ec):
        root_mgr = _make_manager_with_hsm(
            "hsm-root",
            _ca_x509_config("HSM Root CA", path_length=2,
                            aia_url="http://ocsp.root.example.com",
                            crl_url="http://crl.root.example.com/root.crl"),
            p11_client,
        )
        intermediate_mgr = _make_manager_with_hsm(
            "hsm-intermediate",
            _ca_x509_config("HSM Intermediate CA", path_length=0,
                            aia_url="http://ocsp.intermediate.example.com",
                            crl_url="http://crl.intermediate.example.com/intermediate.crl"),
            p11_client,
        )

        # Issue root (self-signed)
        root_csr = root_mgr.create_csr()
        root_cert = root_mgr.sign_csr(signer=None, csr=root_csr, days=3650, is_ca=True)

        # Issue intermediate (signed by root)
        intermediate_csr = intermediate_mgr.create_csr()
        intermediate_cert = root_mgr.sign_csr(
            signer=root_cert, csr=intermediate_csr, days=1825, is_ca=True
        )

        # Issue leaf via external-shape CSR (matches the ACME flow)
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf_csr_crypto = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "leaf.example.com")]))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False, key_agreement=False,
                key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(leaf_key, hashes.SHA384())
        )
        leaf_cert = intermediate_mgr.sign_csr_der(
            signer=intermediate_cert,
            csr_der=leaf_csr_crypto.public_bytes(serialization.Encoding.DER),
            days=90, is_ca=False,
        )

        # Verify each link via cryptography
        from pyasn1.codec.der.encoder import encode as der_encoder
        root_crypto = x509.load_der_x509_certificate(der_encoder(root_cert))
        intermediate_crypto = x509.load_der_x509_certificate(der_encoder(intermediate_cert))
        leaf_crypto = x509.load_der_x509_certificate(der_encoder(leaf_cert))

        root_crypto.verify_directly_issued_by(root_crypto)
        intermediate_crypto.verify_directly_issued_by(root_crypto)
        leaf_crypto.verify_directly_issued_by(intermediate_crypto)

    def test_crl_verifies_against_hsm_signed_root(self, p11_client, requires_ec):
        """CRL signing path uses the same signer pipeline; confirm it
        produces a CRL whose signature verifies against the issuing
        CA's HSM-backed key."""
        from pyasn1.codec.der.encoder import encode as der_encoder

        root_mgr = _make_manager_with_hsm(
            "hsm-crl-root",
            _ca_x509_config("HSM CRL Root", path_length=0),
            p11_client,
        )
        root_csr = root_mgr.create_csr()
        root_cert = root_mgr.sign_csr(signer=None, csr=root_csr, days=3650, is_ca=True)

        crl_asn1 = root_mgr.create_crl(signer=root_cert, revoked_certs=[])
        crl = x509.load_der_x509_crl(der_encoder(crl_asn1))
        root_crypto = x509.load_der_x509_certificate(der_encoder(root_cert))
        assert crl.is_signature_valid(root_crypto.public_key())
