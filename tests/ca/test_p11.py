from __future__ import annotations

import pkcs11
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pkcs11 import Attribute
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ

from ca.p11.key import PKCS11Key, PKCS11PrivKey, PKCS11PubKey

_CURVE_OIDS = {
    "secp256r1": "1.2.840.10045.3.1.7",
    "secp384r1": "1.3.132.0.34",
    "secp521r1": "1.3.132.0.35",
}


def _ec_attributes(crypto_key: ec.EllipticCurvePrivateKey, label: str = "test", key_id: bytes = b"test-id") -> dict:
    """Build the PKCS#11 attribute dict for an EC public key, as a real
    HSM would return it. Used to test PKCS11PubKey.public_bytes() on
    real key material without going through a session."""
    nums = crypto_key.public_key().public_numbers()
    coord_len = (crypto_key.curve.key_size + 7) // 8
    x_bytes = nums.x.to_bytes(coord_len, "big")
    y_bytes = nums.y.to_bytes(coord_len, "big")
    # Uncompressed point: 0x04 || X || Y
    ec_point_raw = b"\x04" + x_bytes + y_bytes
    # PKCS#11 wraps EC_POINT in a DER OctetString (per the spec)
    ec_point_der = der_encoder(univ.OctetString(ec_point_raw))
    ec_params_der = der_encoder(univ.ObjectIdentifier(_CURVE_OIDS[crypto_key.curve.name]))

    return {
        Attribute.LABEL: label,
        Attribute.ID: key_id,
        Attribute.KEY_TYPE: pkcs11.KeyType.EC,
        Attribute.EC_POINT: ec_point_der,
        Attribute.EC_PARAMS: ec_params_der,
    }


def _rsa_attributes(crypto_key: rsa.RSAPrivateKey, label: str = "test", key_id: bytes = b"test-id") -> dict:
    nums = crypto_key.public_key().public_numbers()
    mod_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    exp_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    return {
        Attribute.LABEL: label,
        Attribute.ID: key_id,
        Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
        Attribute.MODULUS: mod_bytes,
        Attribute.PUBLIC_EXPONENT: exp_bytes,
        Attribute.MODULUS_BITS: crypto_key.key_size,
    }


# =========================================================================
# PKCS11Key: base-class behavior
# =========================================================================

class TestPKCS11KeyAttributes:

    def test_label_returned_as_is_when_no_suffix(self):
        """PKCS11Key (the base class) has LABEL_SUFFIX = ''; the label
        passes through unchanged."""
        key = PKCS11Key({Attribute.LABEL: "my-ca-key", Attribute.ID: b"id"})
        assert key.label == "my-ca-key"

    def test_id_returns_attribute_value(self):
        key = PKCS11Key({Attribute.LABEL: "x", Attribute.ID: b"\x01\x02\x03"})
        assert key.id == b"\x01\x02\x03"

    def test_key_type_returns_attribute_value(self):
        key = PKCS11Key({
            Attribute.LABEL: "x", Attribute.ID: b"id",
            Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
        })
        assert key.key_type == pkcs11.KeyType.RSA

    def test_default_attributes_empty_dict(self):
        """The constructor accepts attributes=None and stores an empty
        dict — protects callers that lazily populate."""
        key = PKCS11Key()
        assert key.attributes == {}

    def test_missing_label_attribute_raises(self):
        """A key with no LABEL attribute can't produce its label.
        Documents the failure mode rather than a silent default."""
        key = PKCS11Key({Attribute.ID: b"id"})
        with pytest.raises(KeyError):
            _ = key.label


# =========================================================================
# Label-suffix behavior on PKCS11PubKey and PKCS11PrivKey
# =========================================================================

class TestLabelSuffix:

    def test_pubkey_appends_public_suffix(self):
        pub = PKCS11PubKey({Attribute.LABEL: "my-ca", Attribute.ID: b"id"})
        assert pub.label == "my-ca-public"

    def test_privkey_appends_private_suffix(self):
        priv = PKCS11PrivKey({Attribute.LABEL: "my-ca", Attribute.ID: b"id"})
        assert priv.label == "my-ca-private"

    def test_pubkey_idempotent_when_suffix_present(self):
        """If the label already ends in '-public', don't double-append.
        This matters because attributes round-tripped from PKCS#11
        already carry the suffixed form."""
        pub = PKCS11PubKey({Attribute.LABEL: "my-ca-public", Attribute.ID: b"id"})
        assert pub.label == "my-ca-public"

    def test_privkey_idempotent_when_suffix_present(self):
        priv = PKCS11PrivKey({Attribute.LABEL: "my-ca-private", Attribute.ID: b"id"})
        assert priv.label == "my-ca-private"

    def test_suffix_match_is_strict_endswith(self):
        """'my-publicly-trusted' should NOT skip the suffix even though
        it contains 'public'. Suffix check uses endswith() — verify."""
        pub = PKCS11PubKey({Attribute.LABEL: "my-publicly-trusted", Attribute.ID: b"id"})
        assert pub.label == "my-publicly-trusted-public"


# =========================================================================
# template construction (BASE_TEMPLATE + OVERRIDES + label/id)
# =========================================================================

class TestPubKeyTemplate:

    def _rsa_pub(self, **extra):
        attrs = {
            Attribute.LABEL: "my-ca", Attribute.ID: b"id",
            Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
            **extra,
        }
        return PKCS11PubKey(attrs)

    def _ec_pub(self, **extra):
        attrs = {
            Attribute.LABEL: "my-ca", Attribute.ID: b"id",
            Attribute.KEY_TYPE: pkcs11.KeyType.EC,
            **extra,
        }
        return PKCS11PubKey(attrs)

    def test_base_template_flags_present(self):
        """BASE_TEMPLATE encodes the security-relevant pubkey flags.
        Public keys should be readable (TOKEN=True), public (PRIVATE=
        False), verify-only, never used for wrapping, immutable."""
        tpl = self._rsa_pub().template
        assert tpl[Attribute.TOKEN] is True
        assert tpl[Attribute.PRIVATE] is False
        assert tpl[Attribute.VERIFY] is True
        assert tpl[Attribute.WRAP] is False
        assert tpl[Attribute.MODIFIABLE] is False

    def test_rsa_pubkey_gets_encrypt_attribute(self):
        """The OVERRIDES table adds ENCRYPT=True for RSA pubkeys.
        Without it, a CMS-style encrypt-to-public-key flow couldn't
        use this key."""
        tpl = self._rsa_pub().template
        assert tpl[Attribute.ENCRYPT] is True

    def test_ec_pubkey_no_encrypt_attribute(self):
        """ENCRYPT is only added for RSA; EC keys aren't used for
        bare encryption, so OVERRIDES doesn't apply to them."""
        tpl = self._ec_pub().template
        assert Attribute.ENCRYPT not in tpl

    def test_template_includes_label_and_id(self):
        tpl = self._rsa_pub().template
        # Note: label includes the '-public' suffix (label property)
        assert tpl[Attribute.LABEL] == "my-ca-public"
        assert tpl[Attribute.ID] == b"id"


class TestPrivKeyTemplate:

    def _rsa_priv(self):
        return PKCS11PrivKey({
            Attribute.LABEL: "my-ca", Attribute.ID: b"id",
            Attribute.KEY_TYPE: pkcs11.KeyType.RSA,
        })

    def _ec_priv(self):
        return PKCS11PrivKey({
            Attribute.LABEL: "my-ca", Attribute.ID: b"id",
            Attribute.KEY_TYPE: pkcs11.KeyType.EC,
        })

    def test_base_template_security_flags(self):
        """Private keys: never extractable, sensitive (no read-back),
        sign-only, not used for unwrapping, immutable. These flags
        are what keep the private material inside the HSM — a missing
        or flipped flag would be a serious leak."""
        tpl = self._rsa_priv().template
        assert tpl[Attribute.PRIVATE] is True
        assert tpl[Attribute.TOKEN] is True
        assert tpl[Attribute.SIGN] is True
        assert tpl[Attribute.UNWRAP] is False
        assert tpl[Attribute.EXTRACTABLE] is False
        assert tpl[Attribute.MODIFIABLE] is False
        assert tpl[Attribute.SENSITIVE] is True

    def test_rsa_privkey_gets_decrypt_attribute(self):
        tpl = self._rsa_priv().template
        assert tpl[Attribute.DECRYPT] is True

    def test_ec_privkey_no_decrypt_attribute(self):
        tpl = self._ec_priv().template
        assert Attribute.DECRYPT not in tpl

    def test_template_label_uses_private_suffix(self):
        tpl = self._rsa_priv().template
        assert tpl[Attribute.LABEL] == "my-ca-private"


class TestTemplatePrecedence:
    """The template merges BASE_TEMPLATE | OVERRIDES | label/id, so the
    label/id entries always win and OVERRIDES wins over BASE."""

    def test_label_overrides_anything_in_base(self):
        """If BASE_TEMPLATE accidentally contained a LABEL, the dict
        merge order ensures the final label still wins. Defensive
        test — guards against future BASE_TEMPLATE edits."""

        class WeirdPubKey(PKCS11PubKey):
            BASE_TEMPLATE = {**PKCS11PubKey.BASE_TEMPLATE, Attribute.LABEL: "WRONG"}

        pub = WeirdPubKey({Attribute.LABEL: "right", Attribute.ID: b"id",
                          Attribute.KEY_TYPE: pkcs11.KeyType.RSA})
        assert pub.template[Attribute.LABEL] == "right-public"

    def test_overrides_win_over_base(self):
        """OVERRIDES sits between BASE and label/id in the merge chain,
        so a flag set in OVERRIDES wins over BASE."""

        class WeirdPubKey(PKCS11PubKey):
            BASE_TEMPLATE = {**PKCS11PubKey.BASE_TEMPLATE, Attribute.ENCRYPT: False}

        pub = WeirdPubKey({Attribute.LABEL: "x", Attribute.ID: b"id",
                          Attribute.KEY_TYPE: pkcs11.KeyType.RSA})
        # OVERRIDES[RSA] sets ENCRYPT=True, which should win
        assert pub.template[Attribute.ENCRYPT] is True


# =========================================================================
# PKCS11PubKey.public_bytes() — the actual format conversion logic
# =========================================================================

class TestRsaPublicBytes:

    @pytest.mark.parametrize("bits", [2048, 3072, 4096])
    def test_round_trips_via_cryptography(self, bits):
        """Generate an RSA key with cryptography, marshal its modulus/
        exponent into the PKCS#11 attribute format, then convert back
        through PKCS11PubKey.public_bytes(). The recovered key must
        match the original numbers — proves the byte-order, framing,
        and SPKI construction are all correct."""
        crypto_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        pub = PKCS11PubKey(_rsa_attributes(crypto_key))

        loaded = serialization.load_der_public_key(pub.public_bytes())
        assert isinstance(loaded, rsa.RSAPublicKey)
        assert loaded.key_size == bits
        assert loaded.public_numbers() == crypto_key.public_key().public_numbers()

    def test_output_is_valid_spki(self):
        """SPKI DER starts with a SEQUENCE tag (0x30). Quick sanity
        check that public_bytes() returns a wrapped SPKI, not just
        the raw modulus bytes."""
        crypto_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        spki_der = PKCS11PubKey(_rsa_attributes(crypto_key)).public_bytes()
        assert spki_der[0] == 0x30


class TestEcPublicBytes:

    @pytest.mark.parametrize("curve_name,curve_cls", [
        ("secp256r1", ec.SECP256R1),
        ("secp384r1", ec.SECP384R1),
        ("secp521r1", ec.SECP521R1),
    ])
    def test_round_trips_via_cryptography(self, curve_name, curve_cls):
        """Same round-trip check as RSA, parametrized across the three
        common curves to catch any coordinate-length assumptions in
        public_bytes(). P-521's 66-byte coordinates are the most
        likely to surface an off-by-one bug."""
        crypto_key = ec.generate_private_key(curve_cls())
        pub = PKCS11PubKey(_ec_attributes(crypto_key), ec_curve=curve_name)

        loaded = serialization.load_der_public_key(pub.public_bytes())
        assert isinstance(loaded, ec.EllipticCurvePublicKey)
        assert loaded.curve.name == curve_name
        assert loaded.public_numbers() == crypto_key.public_key().public_numbers()

    def test_output_is_valid_spki(self):
        crypto_key = ec.generate_private_key(ec.SECP256R1())
        spki_der = PKCS11PubKey(_ec_attributes(crypto_key), ec_curve="secp256r1").public_bytes()
        assert spki_der[0] == 0x30


class TestUnsupportedKeyType:

    def test_dh_key_type_raises(self):
        pub = PKCS11PubKey({
            Attribute.LABEL: "x", Attribute.ID: b"id",
            Attribute.KEY_TYPE: pkcs11.KeyType.DH,
        })
        with pytest.raises(ValueError, match="Unsupported key type"):
            pub.public_bytes()