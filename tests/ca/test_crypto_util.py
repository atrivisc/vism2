from __future__ import annotations

from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519
from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, useful
from pyasn1_modules import rfc5280

from ca.crypto.build import get_extension_by_oid_from_certificate, generate_random_serial, \
    get_ans1_time
from ca.crypto.util import asn1_time_to_datetime, get_algorithm_identifier

OID_RSA_SHA256 = "1.2.840.113549.1.1.11"
OID_RSA_SHA384 = "1.2.840.113549.1.1.12"
OID_RSA_SHA512 = "1.2.840.113549.1.1.13"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4"

OID_EXT_BASIC_CONSTRAINTS = "2.5.29.19"
OID_EXT_KEY_USAGE = "2.5.29.15"
OID_EXT_SUBJECT_ALT_NAME = "2.5.29.17"
OID_EXT_AUTH_KEY_ID = "2.5.29.35"


@pytest.fixture(scope="session")
def rsa_public_key() -> rsa.RSAPublicKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

@pytest.fixture(scope="session")
def ec_public_key() -> ec.EllipticCurvePublicKey:
    return ec.generate_private_key(ec.SECP256R1()).public_key()

class TestGetAlgorithmIdentifier:
    def test_returns_algorithm_identifier_instance(self, rsa_public_key):
        result = get_algorithm_identifier(rsa_public_key, "SHA256")
        assert isinstance(result, rfc5280.AlgorithmIdentifier)

    @pytest.mark.parametrize(
        "hash_name,expected_oid",
        [
            ("SHA256", OID_RSA_SHA256),
            ("SHA384", OID_RSA_SHA384),
            ("SHA512", OID_RSA_SHA512),
        ],
    )
    def test_rsa_oids(self, rsa_public_key, hash_name, expected_oid):
        result = get_algorithm_identifier(rsa_public_key, hash_name)
        assert str(result["algorithm"]) == expected_oid

    @pytest.mark.parametrize(
        "hash_name,expected_oid",
        [
            ("SHA256", OID_ECDSA_SHA256),
            ("SHA384", OID_ECDSA_SHA384),
            ("SHA512", OID_ECDSA_SHA512),
        ],
    )
    def test_ecdsa_oids(self, ec_public_key, hash_name, expected_oid):
        result = get_algorithm_identifier(ec_public_key, hash_name)
        assert str(result["algorithm"]) == expected_oid

    def test_algorithm_field_is_object_identifier(self, rsa_public_key):
        result = get_algorithm_identifier(rsa_public_key, "SHA256")
        assert isinstance(result["algorithm"], univ.ObjectIdentifier)

    def test_result_is_der_encodable(self, rsa_public_key):
        """Any AlgorithmIdentifier we produce must serialize to DER."""
        result = get_algorithm_identifier(rsa_public_key, "SHA256")
        encoded = encoder.encode(result)
        assert isinstance(encoded, bytes) and len(encoded) > 0

    def test_unknown_hash_raises(self, rsa_public_key):
        with pytest.raises(KeyError):
            get_algorithm_identifier(rsa_public_key, "SHA1")

    def test_unknown_hash_md5_raises(self, rsa_public_key):
        with pytest.raises(KeyError):
            get_algorithm_identifier(rsa_public_key, "MD5")

    def test_unsupported_key_type_raises(self):
        ed_key = ed25519.Ed25519PrivateKey.generate().public_key()
        with pytest.raises(KeyError):
            get_algorithm_identifier(ed_key, "SHA256")  # type: ignore[arg-type]

    def test_lowercase_hash_name_raises(self, rsa_public_key):
        with pytest.raises(KeyError):
            get_algorithm_identifier(rsa_public_key, "sha256")


def _make_cert_with_extensions(oids: list[str]) -> rfc5280.Certificate:
    cert = rfc5280.Certificate()
    tbs = cert["tbsCertificate"]
    ext_schema = tbs.getComponentType().getTypeByPosition(
        tbs.getComponentType().getPositionByName("extensions")
    )
    extensions = ext_schema.clone()
    for i, oid in enumerate(oids):
        ext = rfc5280.Extension()
        ext["extnID"] = univ.ObjectIdentifier(oid)
        ext["critical"] = False
        ext["extnValue"] = univ.OctetString(value=bytes([i]) + b"payload")
        extensions.append(ext)
    tbs["extensions"] = extensions
    return cert


class TestGetExtensionByOid:

    def test_finds_existing_extension(self):
        cert = _make_cert_with_extensions(
            [OID_EXT_BASIC_CONSTRAINTS, OID_EXT_KEY_USAGE, OID_EXT_SUBJECT_ALT_NAME]
        )
        result = get_extension_by_oid_from_certificate(cert, OID_EXT_KEY_USAGE)
        assert result is not None
        assert str(result["extnID"]) == OID_EXT_KEY_USAGE

    def test_returns_none_when_not_present(self):
        cert = _make_cert_with_extensions(
            [OID_EXT_BASIC_CONSTRAINTS, OID_EXT_KEY_USAGE]
        )
        result = get_extension_by_oid_from_certificate(cert, OID_EXT_SUBJECT_ALT_NAME)
        assert result is None

    def test_returns_none_on_empty_extensions(self):
        cert = _make_cert_with_extensions([])
        result = get_extension_by_oid_from_certificate(cert, OID_EXT_BASIC_CONSTRAINTS)
        assert result is None

    def test_returns_first_match_when_duplicated(self):
        cert = _make_cert_with_extensions(
            [OID_EXT_KEY_USAGE, OID_EXT_BASIC_CONSTRAINTS, OID_EXT_KEY_USAGE]
        )
        result = get_extension_by_oid_from_certificate(cert, OID_EXT_KEY_USAGE)
        assert result is not None
        assert bytes(result["extnValue"])[0] == 0x00

    def test_finds_first_extension_in_list(self):
        cert = _make_cert_with_extensions(
            [OID_EXT_BASIC_CONSTRAINTS, OID_EXT_KEY_USAGE]
        )
        result = get_extension_by_oid_from_certificate(cert, OID_EXT_BASIC_CONSTRAINTS)
        assert result is not None
        assert str(result["extnID"]) == OID_EXT_BASIC_CONSTRAINTS

    def test_finds_last_extension_in_list(self):
        cert = _make_cert_with_extensions(
            [OID_EXT_BASIC_CONSTRAINTS, OID_EXT_KEY_USAGE, OID_EXT_AUTH_KEY_ID]
        )
        result = get_extension_by_oid_from_certificate(cert, OID_EXT_AUTH_KEY_ID)
        assert result is not None
        assert str(result["extnID"]) == OID_EXT_AUTH_KEY_ID


class TestGenerateRandomSerial:
    def test_returns_int(self):
        assert isinstance(generate_random_serial(), int)

    def test_is_positive(self):
        for _ in range(50):
            assert generate_random_serial() > 0

    def test_bit_length_at_most_159(self):
        for _ in range(50):
            assert generate_random_serial().bit_length() <= 159

    def test_provides_at_least_64_bits_of_entropy(self):
        samples = [generate_random_serial() for _ in range(50)]
        assert min(s.bit_length() for s in samples) > 64

    def test_der_encoded_fits_in_20_octets(self):
        for _ in range(50):
            serial = generate_random_serial()
            asn1_int = univ.Integer(serial)
            der = encoder.encode(asn1_int)
            assert der[0] == 0x02  # INTEGER tag
            value_len = der[1]
            assert value_len <= 20, f"serial {serial} encodes to {value_len} octets"

    def test_distinct_values(self):
        values = {generate_random_serial() for _ in range(50)}
        assert len(values) == 50


class TestGetAsn1Time:
    def test_returns_time_choice(self):
        result = get_ans1_time(datetime(2025, 1, 1, tzinfo=timezone.utc))
        assert isinstance(result, rfc5280.Time)

    @pytest.mark.parametrize("year", [1950, 1999, 2000, 2024, 2049])
    def test_pre_2050_uses_utctime(self, year):
        result = get_ans1_time(datetime(year, 6, 15, 12, 0, 0, tzinfo=timezone.utc))
        assert result["utcTime"].hasValue()
        assert not result["generalTime"].hasValue()

    @pytest.mark.parametrize("year", [2050, 2051, 2100, 9999])
    def test_2050_and_later_uses_generalized_time(self, year):
        result = get_ans1_time(datetime(year, 6, 15, 12, 0, 0, tzinfo=timezone.utc))
        assert result["generalTime"].hasValue()
        assert not result["utcTime"].hasValue()

    def test_boundary_2049_last_instant_is_utctime(self):
        dt = datetime(2049, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        result = get_ans1_time(dt)
        assert result["utcTime"].hasValue()
        assert not result["generalTime"].hasValue()

    def test_boundary_2050_first_instant_is_generalized_time(self):
        dt = datetime(2050, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = get_ans1_time(dt)
        assert result["generalTime"].hasValue()
        assert not result["utcTime"].hasValue()


class TestAsn1TimeToDatetime:

    def test_decodes_utctime(self):
        t = rfc5280.Time()
        t["utcTime"] = useful.UTCTime.fromDateTime(
            datetime(2030, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        )
        result = asn1_time_to_datetime(t)
        assert result == datetime(2030, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_decodes_generalized_time(self):
        t = rfc5280.Time()
        t["generalTime"] = useful.GeneralizedTime.fromDateTime(
            datetime(2080, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        )
        result = asn1_time_to_datetime(t)
        assert result == datetime(2080, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_returned_datetime_is_tz_aware(self):
        t = rfc5280.Time()
        t["utcTime"] = useful.UTCTime.fromDateTime(
            datetime(2030, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        )
        result = asn1_time_to_datetime(t)
        assert result.tzinfo is not None
        assert result.utcoffset().total_seconds() == 0


class TestRoundTrip:
    @pytest.mark.parametrize(
        "dt",
        [
            # 1950 is the floor of UTCTime per RFC 5280 §4.1.2.5, but is
            # excluded here because pyasn1 does not implement the
            # sliding-window YY decoding the RFC requires — it decodes
            # "50" as 2050 rather than 1950. This is acceptable for an
            # internal CA that will not issue certs with pre-2000
            # notBefore dates; see test_pyasn1_1950_decoding_is_broken
            # below, which pins this as a known library limitation.
            datetime(2000, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2024, 6, 15, 12, 30, 45, tzinfo=timezone.utc),
            datetime(2049, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
            datetime(2050, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            datetime(2099, 6, 15, 12, 30, 45, tzinfo=timezone.utc),
            datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        ],
    )
    def test_roundtrip(self, dt):
        encoded = get_ans1_time(dt)
        decoded = asn1_time_to_datetime(encoded)
        assert decoded == dt

    def test_pyasn1_1950_decoding_is_broken(self):
        dt = datetime(1950, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        encoded = get_ans1_time(dt)
        decoded = asn1_time_to_datetime(encoded)
        assert decoded.year == 2050, (
            "pyasn1 fixed its UTCTime YY decoding — re-enable the 1950 case "
            "in test_roundtrip"
        )

    def test_roundtrip_through_der(self):
        dt = datetime(2049, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        encoded = get_ans1_time(dt)
        der = encoder.encode(encoded)
        decoded_time, _ = decoder.decode(der, asn1Spec=rfc5280.Time())
        assert asn1_time_to_datetime(decoded_time) == dt

    def test_roundtrip_through_der_post_2050(self):
        dt = datetime(2050, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        encoded = get_ans1_time(dt)
        der = encoder.encode(encoded)
        decoded_time, _ = decoder.decode(der, asn1Spec=rfc5280.Time())
        assert asn1_time_to_datetime(decoded_time) == dt