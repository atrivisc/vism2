from __future__ import annotations

from datetime import datetime, timedelta, timezone

import hashlib
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import char, tag, univ
from pyasn1_modules import rfc5280, rfc2986

from ca.asn1 import RevokedCertificateEntry
from ca.crypto.build import (
    CERT_VERSION,
    CRL_VERSION,
    CSR_VERSION,
    build_certification_request_info,
    build_revoked_certificate_entry,
    build_tbs_cert_list,
    build_tbs_certificate,
)
from ca.crypto.util import get_algorithm_identifier
from ca.errors import CryptoException


OID_EXT_REQUEST = "1.2.840.113549.1.9.14"
OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14"
OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1"
OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31"
OID_CRL_REASON = "2.5.29.21"
OID_OCSP = "1.3.6.1.5.5.7.48.1"
OID_COMMON_NAME = "2.5.4.3"


def _make_name(cn: str) -> rfc5280.Name:
    name = rfc5280.Name()
    rdns = rfc5280.RDNSequence()
    rdn = rfc5280.RelativeDistinguishedName()
    atv = rfc5280.AttributeTypeAndValue()
    atv["type"] = univ.ObjectIdentifier(OID_COMMON_NAME)
    atv["value"] = char.UTF8String(cn)
    rdn.append(atv)
    rdns.append(rdn)
    name["rdnSequence"] = rdns
    return name


def _make_basic_constraints_ext(ca: bool = True, path_len: int | None = None) -> rfc5280.Extension:
    bc = rfc5280.BasicConstraints()
    bc.setComponentByName("cA", ca)
    if path_len is not None:
        bc.setComponentByName("pathLenConstraint", path_len)
    ext = rfc5280.Extension()
    ext["extnID"] = univ.ObjectIdentifier(OID_BASIC_CONSTRAINTS)
    ext["critical"] = True
    ext["extnValue"] = univ.OctetString(der_encoder(bc))
    return ext


def _uri_general_name(url: str) -> rfc5280.GeneralName:
    gn = rfc5280.GeneralName()
    uri = char.IA5String(url).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
    )
    gn.setComponentByName("uniformResourceIdentifier", uri)
    return gn


def _make_aia_ext(url: str = "http://ocsp.example.com") -> rfc5280.Extension:
    aia = rfc5280.AuthorityInfoAccessSyntax()
    ad = rfc5280.AccessDescription()
    ad["accessMethod"] = univ.ObjectIdentifier(OID_OCSP)
    ad["accessLocation"] = _uri_general_name(url)
    aia.append(ad)
    ext = rfc5280.Extension()
    ext["extnID"] = univ.ObjectIdentifier(OID_AUTHORITY_INFO_ACCESS)
    ext["extnValue"] = univ.OctetString(der_encoder(aia))
    return ext


def _make_crldp_ext(url: str = "http://crl.example.com/root.crl") -> rfc5280.Extension:
    dp = rfc5280.DistributionPoint()
    dpn_schema = dp.getComponentType().getTypeByPosition(
        dp.getComponentType().getPositionByName("distributionPoint")
    )
    dpn = dpn_schema.clone()
    fn_schema = dpn.getComponentType().getTypeByPosition(
        dpn.getComponentType().getPositionByName("fullName")
    )
    full = fn_schema.clone()
    full.append(_uri_general_name(url))
    dpn.setComponentByName("fullName", full)
    dp.setComponentByName("distributionPoint", dpn)
    crldp = rfc5280.CRLDistributionPoints()
    crldp.append(dp)
    ext = rfc5280.Extension()
    ext["extnID"] = univ.ObjectIdentifier(OID_CRL_DISTRIBUTION_POINTS)
    ext["extnValue"] = univ.OctetString(der_encoder(crldp))
    return ext


def _build_csr(
    key: ec.EllipticCurvePrivateKey,
    cn: str,
    extensions: list[rfc5280.Extension] | None = None,
) -> rfc2986.CertificationRequest:
    if extensions is None:
        extensions = [_make_basic_constraints_ext(ca=True, path_len=0)]
    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    csr_info = build_certification_request_info(
        subject=_make_name(cn),
        requested_extensions=extensions,
        public_key_bytes=pub_bytes,
    )
    csr = rfc2986.CertificationRequest()
    csr["certificationRequestInfo"] = csr_info
    csr["signatureAlgorithm"] = get_algorithm_identifier(key.public_key(), "SHA256")
    csr["signature"] = univ.BitString(hexValue="00")
    csr_der = der_encoder(csr)
    decoded, _ = der_decoder(csr_der, asn1Spec=rfc2986.CertificationRequest())
    return decoded


def _build_issuer_cert(
    key: ec.EllipticCurvePrivateKey,
    cn: str = "Test Root CA",
    include_skid: bool = True,
    aia_ext: rfc5280.Extension | None = None,
    crldp_ext: rfc5280.Extension | None = None,
) -> rfc5280.Certificate:
    cert = rfc5280.Certificate()
    tbs = cert["tbsCertificate"]
    tbs["version"] = CERT_VERSION
    tbs["serialNumber"] = rfc5280.CertificateSerialNumber(1)
    tbs["signature"] = get_algorithm_identifier(key.public_key(), "SHA256")
    tbs["issuer"] = _make_name(cn)
    tbs["subject"] = _make_name(cn)

    pub_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki, _ = der_decoder(pub_der, asn1Spec=rfc5280.SubjectPublicKeyInfo())
    tbs["subjectPublicKeyInfo"] = spki

    validity = rfc5280.Validity()
    from ca.crypto.util import get_ans1_time
    validity["notBefore"] = get_ans1_time(datetime(2024, 1, 1, tzinfo=timezone.utc))
    validity["notAfter"] = get_ans1_time(datetime(2034, 1, 1, tzinfo=timezone.utc))
    tbs["validity"] = validity

    ext_schema = tbs.getComponentType().getTypeByPosition(
        tbs.getComponentType().getPositionByName("extensions")
    )
    exts = ext_schema.clone()

    if include_skid:
        skid_value = hashlib.sha1(der_encoder(spki)).digest()
        skid_ext = rfc5280.Extension()
        skid_ext["extnID"] = univ.ObjectIdentifier(OID_SUBJECT_KEY_IDENTIFIER)
        skid_ext["extnValue"] = univ.OctetString(
            der_encoder(rfc5280.SubjectKeyIdentifier(skid_value))
        )
        exts.append(skid_ext)

    if aia_ext is not None:
        exts.append(aia_ext)
    if crldp_ext is not None:
        exts.append(crldp_ext)

    if len(exts) > 0:
        tbs["extensions"] = exts

    cert["signatureAlgorithm"] = get_algorithm_identifier(key.public_key(), "SHA256")
    cert["signature"] = univ.BitString(hexValue="00")
    return cert


@pytest.fixture(scope="session")
def issuer_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def subject_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="session")
def issuer_aia_ext() -> rfc5280.Extension:
    return _make_aia_ext("http://ocsp.issuer.example.com")


@pytest.fixture(scope="session")
def issuer_crldp_ext() -> rfc5280.Extension:
    return _make_crldp_ext("http://crl.issuer.example.com/root.crl")


@pytest.fixture(scope="session")
def issuer_cert(issuer_key, issuer_aia_ext, issuer_crldp_ext) -> rfc5280.Certificate:
    return _build_issuer_cert(
        issuer_key,
        cn="Test Root CA",
        include_skid=True,
        aia_ext=issuer_aia_ext,
        crldp_ext=issuer_crldp_ext,
    )


@pytest.fixture(scope="session")
def subject_csr(subject_key) -> rfc2986.CertificationRequest:
    return _build_csr(subject_key, "Test Leaf")


@pytest.fixture(scope="session")
def issuer_self_csr(issuer_key) -> rfc2986.CertificationRequest:
    return _build_csr(issuer_key, "Test Root CA")


def _get_ext(tbs: rfc5280.TBSCertificate, oid: str) -> rfc5280.Extension | None:
    for ext in tbs["extensions"]:
        if str(ext["extnID"]) == oid:
            return ext
    return None


def _all_ext_oids(tbs: rfc5280.TBSCertificate) -> list[str]:
    return [str(ext["extnID"]) for ext in tbs["extensions"]]


def _sig_alg():
    return get_algorithm_identifier(
        ec.generate_private_key(ec.SECP256R1()).public_key(), "SHA256"
    )


def _build(issuer_cert, csr, *, days=90, signature_algorithm=None, **kwargs):
    return build_tbs_certificate(
        issuer_cert=issuer_cert,
        csr=csr,
        days=days,
        signature_algorithm=signature_algorithm or _sig_alg(),
        **kwargs,
    )

class TestBuildCertificationRequestInfo:

    def test_version_set(self, subject_key):
        pub_bytes = subject_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        info = build_certification_request_info(
            subject=_make_name("Test"),
            requested_extensions=[_make_basic_constraints_ext()],
            public_key_bytes=pub_bytes,
        )
        assert int(info["version"]) == CSR_VERSION

    def test_subject_set(self, subject_key):
        pub_bytes = subject_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        info = build_certification_request_info(
            subject=_make_name("Subject CN"),
            requested_extensions=[_make_basic_constraints_ext()],
            public_key_bytes=pub_bytes,
        )
        encoded_subject = der_encoder(info["subject"])
        expected_subject = der_encoder(_make_name("Subject CN"))
        assert encoded_subject == expected_subject

    def test_spki_set(self, subject_key):
        pub_bytes = subject_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        info = build_certification_request_info(
            subject=_make_name("Test"),
            requested_extensions=[_make_basic_constraints_ext()],
            public_key_bytes=pub_bytes,
        )
        assert der_encoder(info["subjectPKInfo"]) == pub_bytes

    def test_extension_request_attribute_present(self, subject_key):
        pub_bytes = subject_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        info = build_certification_request_info(
            subject=_make_name("Test"),
            requested_extensions=[_make_basic_constraints_ext()],
            public_key_bytes=pub_bytes,
        )
        attrs = info["attributes"]
        oids = [str(a["type"]) for a in attrs]
        assert OID_EXT_REQUEST in oids

    def test_none_entries_skipped(self, subject_key):
        pub_bytes = subject_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        bc = _make_basic_constraints_ext()
        info = build_certification_request_info(
            subject=_make_name("Test"),
            requested_extensions=[None, bc, None],
            public_key_bytes=pub_bytes,
        )

        der = der_encoder(info)
        decoded, _ = der_decoder(der, asn1Spec=rfc2986.CertificationRequestInfo())
        ext_attr = next(a for a in decoded["attributes"] if str(a["type"]) == OID_EXT_REQUEST)
        extensions_set, _ = der_decoder(ext_attr["values"][0], asn1Spec=rfc5280.Extensions())
        assert len(extensions_set) == 1
        assert str(extensions_set[0]["extnID"]) == OID_BASIC_CONSTRAINTS

    def test_result_round_trips_through_csr(self, subject_key):
        pub_bytes = subject_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        info = build_certification_request_info(
            subject=_make_name("Test"),
            requested_extensions=[_make_basic_constraints_ext()],
            public_key_bytes=pub_bytes,
        )
        csr = rfc2986.CertificationRequest()
        csr["certificationRequestInfo"] = info
        csr["signatureAlgorithm"] = get_algorithm_identifier(subject_key.public_key(), "SHA256")
        csr["signature"] = univ.BitString(hexValue="00")
        csr_der = der_encoder(csr)
        assert isinstance(csr_der, bytes) and len(csr_der) > 0

    def test_empty_extensions_produces_encodable_csr(self, subject_key):
        pub_bytes = subject_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        info = build_certification_request_info(
            subject=_make_name("Test"),
            requested_extensions=[],
            public_key_bytes=pub_bytes,
        )
        csr = rfc2986.CertificationRequest()
        csr["certificationRequestInfo"] = info
        csr["signatureAlgorithm"] = get_algorithm_identifier(subject_key.public_key(), "SHA256")
        csr["signature"] = univ.BitString(hexValue="00")
        der = der_encoder(csr)
        assert isinstance(der, bytes) and len(der) > 0


class TestBuildTbsCertificateBasics:

    def test_version_is_v3(self, issuer_cert, subject_csr):
        tbs = _build(issuer_cert, subject_csr)
        assert int(tbs["version"]) == CERT_VERSION

    def test_signature_algorithm_set(self, issuer_cert, subject_csr):
        sig_alg = get_algorithm_identifier(
            ec.generate_private_key(ec.SECP256R1()).public_key(), "SHA384"
        )
        tbs = _build(issuer_cert, subject_csr, signature_algorithm=sig_alg)
        assert der_encoder(tbs["signature"]) == der_encoder(sig_alg)

    def test_serial_provided_value_used(self, issuer_cert, subject_csr):
        tbs = _build(issuer_cert, subject_csr, serial=12345)
        assert int(tbs["serialNumber"]) == 12345

    def test_serial_random_when_not_provided(self, issuer_cert, subject_csr):
        sig = _sig_alg()
        t1 = _build(issuer_cert, subject_csr, signature_algorithm=sig)
        t2 = _build(issuer_cert, subject_csr, signature_algorithm=sig)
        assert int(t1["serialNumber"]) != int(t2["serialNumber"])

    def test_serial_is_positive(self, issuer_cert, subject_csr):
        sig = _sig_alg()
        for _ in range(20):
            tbs = _build(issuer_cert, subject_csr, signature_algorithm=sig)
            assert int(tbs["serialNumber"]) > 0

    def test_subject_from_csr(self, issuer_cert, subject_csr):
        tbs = _build(issuer_cert, subject_csr)
        csr_subject_der = der_encoder(subject_csr["certificationRequestInfo"]["subject"])
        assert der_encoder(tbs["subject"]) == csr_subject_der

    def test_subjectPublicKeyInfo_from_csr(self, issuer_cert, subject_csr):
        tbs = _build(issuer_cert, subject_csr)
        csr_spki_der = der_encoder(subject_csr["certificationRequestInfo"]["subjectPKInfo"])
        assert der_encoder(tbs["subjectPublicKeyInfo"]) == csr_spki_der

    def test_issuer_from_issuer_cert_when_provided(self, issuer_cert, subject_csr):
        tbs = _build(issuer_cert, subject_csr)
        expected_issuer_der = der_encoder(issuer_cert["tbsCertificate"]["subject"])
        assert der_encoder(tbs["issuer"]) == expected_issuer_der

    def test_issuer_from_csr_subject_when_self_signed(self, issuer_self_csr):
        """Self-signed root: issuer = subject (RFC 5280 §3.2)."""
        tbs = _build(None, issuer_self_csr, days=3650)
        assert der_encoder(tbs["issuer"]) == der_encoder(tbs["subject"])

    def test_tbs_is_der_encodable(self, issuer_cert, subject_csr):
        tbs = _build(issuer_cert, subject_csr)
        der = der_encoder(tbs)
        decoded, _ = der_decoder(der, asn1Spec=rfc5280.TBSCertificate())
        assert int(decoded["serialNumber"]) == int(tbs["serialNumber"])


class TestValidity:

    def test_not_before_one_hour_before_now(self, issuer_cert, subject_csr):
        now = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        tbs = _build(issuer_cert, subject_csr, now=now)
        from ca.crypto.util import asn1_time_to_datetime
        not_before = asn1_time_to_datetime(tbs["validity"]["notBefore"])
        assert not_before == now - timedelta(hours=1)

    def test_not_after_days_after_now(self, issuer_cert, subject_csr):
        now = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        tbs = _build(issuer_cert, subject_csr, now=now)
        from ca.crypto.util import asn1_time_to_datetime
        not_after = asn1_time_to_datetime(tbs["validity"]["notAfter"])
        assert not_after == now + timedelta(days=90)

    def test_not_before_before_not_after(self, issuer_cert, subject_csr):
        tbs = _build(issuer_cert, subject_csr, days=1)
        from ca.crypto.util import asn1_time_to_datetime
        nb = asn1_time_to_datetime(tbs["validity"]["notBefore"])
        na = asn1_time_to_datetime(tbs["validity"]["notAfter"])
        assert nb < na


class TestSubjectKeyIdentifier:
    def test_skid_extension_present(self, issuer_cert, subject_csr):
        tbs = _build(issuer_cert, subject_csr)
        assert _get_ext(tbs, OID_SUBJECT_KEY_IDENTIFIER) is not None

    def test_skid_value_is_sha1_of_full_spki_der(self, issuer_cert, subject_csr, subject_key):
        tbs = _build(issuer_cert, subject_csr)
        skid_ext = _get_ext(tbs, OID_SUBJECT_KEY_IDENTIFIER)
        skid_value_decoded, _ = der_decoder(
            skid_ext["extnValue"], asn1Spec=rfc5280.SubjectKeyIdentifier()
        )
        actual = bytes(skid_value_decoded)

        spki_der = subject_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected = hashlib.sha1(spki_der).digest()

        assert actual == expected
        assert len(actual) == 20

    def test_skid_length_is_20_bytes(self, issuer_cert, subject_csr):
        tbs = _build(issuer_cert, subject_csr)
        skid_ext = _get_ext(tbs, OID_SUBJECT_KEY_IDENTIFIER)
        decoded, _ = der_decoder(skid_ext["extnValue"], asn1Spec=rfc5280.SubjectKeyIdentifier())
        assert len(bytes(decoded)) == 20

    def test_skid_self_signed_matches_subject_spki(self, issuer_self_csr, issuer_key):
        tbs = _build(None, issuer_self_csr, days=3650)
        skid_ext = _get_ext(tbs, OID_SUBJECT_KEY_IDENTIFIER)
        skid_value_decoded, _ = der_decoder(
            skid_ext["extnValue"], asn1Spec=rfc5280.SubjectKeyIdentifier()
        )
        actual = bytes(skid_value_decoded)

        spki_der = issuer_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected = hashlib.sha1(spki_der).digest()
        assert actual == expected


class TestAuthorityKeyIdentifier:

    def test_akid_present_when_issuer_cert_provided(self, issuer_cert, subject_csr):
        tbs = _build(issuer_cert, subject_csr)
        assert _get_ext(tbs, OID_AUTHORITY_KEY_IDENTIFIER) is not None

    def test_akid_absent_for_self_signed(self, issuer_self_csr):
        tbs = _build(None, issuer_self_csr, days=3650)
        assert _get_ext(tbs, OID_AUTHORITY_KEY_IDENTIFIER) is None

    def test_akid_matches_issuer_skid(self, issuer_cert, issuer_key, subject_csr):
        tbs = _build(issuer_cert, subject_csr)
        akid_ext = _get_ext(tbs, OID_AUTHORITY_KEY_IDENTIFIER)
        akid_decoded, _ = der_decoder(akid_ext["extnValue"], asn1Spec=rfc5280.AuthorityKeyIdentifier())
        akid_kid = bytes(akid_decoded["keyIdentifier"])

        issuer_pub_der = issuer_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected = hashlib.sha1(issuer_pub_der).digest()

        assert akid_kid == expected

    def test_raises_when_issuer_lacks_skid(self, issuer_key, subject_csr):
        issuer_no_skid = _build_issuer_cert(
            issuer_key, cn="Bad Issuer", include_skid=False,
            aia_ext=_make_aia_ext(), crldp_ext=_make_crldp_ext(),
        )
        with pytest.raises(CryptoException):
            _build(issuer_no_skid, subject_csr)


class TestRequestedExtensionsCarryover:

    def test_basic_constraints_carried_from_csr(self, issuer_cert, subject_key):
        bc_ext = _make_basic_constraints_ext(ca=True, path_len=2)
        csr = _build_csr(subject_key, "With BC", extensions=[bc_ext])
        tbs = _build(issuer_cert, csr)
        ext = _get_ext(tbs, OID_BASIC_CONSTRAINTS)
        assert ext is not None
        bc_decoded, _ = der_decoder(ext["extnValue"], asn1Spec=rfc5280.BasicConstraints())
        assert bool(bc_decoded["cA"]) is True
        assert int(bc_decoded["pathLenConstraint"]) == 2

    def test_multiple_extensions_carried(self, issuer_cert, subject_key):
        bc = _make_basic_constraints_ext()
        ku = rfc5280.Extension()
        ku["extnID"] = univ.ObjectIdentifier(OID_KEY_USAGE)
        ku["critical"] = True
        ku_val = rfc5280.KeyUsage("100000000")  # digitalSignature
        ku["extnValue"] = univ.OctetString(der_encoder(ku_val))
        csr = _build_csr(subject_key, "Multi", extensions=[bc, ku])
        tbs = _build(issuer_cert, csr)
        assert _get_ext(tbs, OID_BASIC_CONSTRAINTS) is not None
        assert _get_ext(tbs, OID_KEY_USAGE) is not None

    def test_ca_cert_carries_aia_crldp_from_csr(self, issuer_cert, subject_key):
        aia = _make_aia_ext("http://ocsp.intermediate.example.com")
        crldp = _make_crldp_ext("http://crl.intermediate.example.com/x.crl")
        bc = _make_basic_constraints_ext(ca=True, path_len=0)
        csr = _build_csr(subject_key, "Intermediate", extensions=[bc, aia, crldp])

        tbs = _build(issuer_cert, csr)
        oids = _all_ext_oids(tbs)
        assert oids.count(OID_AUTHORITY_INFO_ACCESS) == 1
        assert oids.count(OID_CRL_DISTRIBUTION_POINTS) == 1

    def test_ca_cert_no_double_aia_crldp_with_explicit_kwargs(self, issuer_cert, subject_key):
        aia = _make_aia_ext("http://ocsp.intermediate.example.com")
        crldp = _make_crldp_ext("http://crl.intermediate.example.com/x.crl")
        bc = _make_basic_constraints_ext(ca=True, path_len=0)
        csr = _build_csr(subject_key, "Intermediate", extensions=[bc, aia, crldp])

        tbs = _build(
            issuer_cert, csr,
            additional_extensions = [
                _make_aia_ext("http://ocsp.other.example.com"),
                _make_crldp_ext("http://crl.other.example.com/y.crl"),
            ],
        )
        oids = _all_ext_oids(tbs)
        assert oids.count(OID_AUTHORITY_INFO_ACCESS) == 1
        assert oids.count(OID_CRL_DISTRIBUTION_POINTS) == 1

class TestLeafCrlDistributionPoints:

    def test_inherited_from_issuer_when_not_given(self, issuer_cert, issuer_crldp_ext, subject_csr):
        tbs = _build(issuer_cert, subject_csr)
        crldp_ext = _get_ext(tbs, OID_CRL_DISTRIBUTION_POINTS)
        assert crldp_ext is not None
        assert bytes(crldp_ext["extnValue"]) == bytes(issuer_crldp_ext["extnValue"])

    def test_explicit_used_when_issuer_lacks_it(self, issuer_key, subject_csr):
        issuer_no_crldp = _build_issuer_cert(
            issuer_key, include_skid=True, aia_ext=_make_aia_ext(), crldp_ext=None
        )
        fallback = _make_crldp_ext("http://crl.fallback.example.com/x.crl")
        tbs = _build(
            issuer_no_crldp, subject_csr,
            additional_extensions = [
                fallback,
            ]
        )
        crldp_ext = _get_ext(tbs, OID_CRL_DISTRIBUTION_POINTS)
        assert crldp_ext is not None
        assert bytes(crldp_ext["extnValue"]) == bytes(fallback["extnValue"])

    def test_omitted_when_no_source(self, issuer_key, subject_csr):
        issuer_no_crldp = _build_issuer_cert(
            issuer_key, include_skid=True, aia_ext=None, crldp_ext=None
        )
        tbs = _build(issuer_no_crldp, subject_csr)
        assert _get_ext(tbs, OID_CRL_DISTRIBUTION_POINTS) is None


class TestSelfSignedRoot:

    def test_root_builds_with_aia_crldp_in_csr(self, issuer_key, issuer_aia_ext, issuer_crldp_ext):
        bc = _make_basic_constraints_ext(ca=True, path_len=2)
        csr = _build_csr(issuer_key, "Root CA", extensions=[bc, issuer_aia_ext, issuer_crldp_ext])
        tbs = _build(None, csr, days=3650)

        oids = _all_ext_oids(tbs)
        assert OID_SUBJECT_KEY_IDENTIFIER in oids
        assert OID_BASIC_CONSTRAINTS in oids
        assert OID_AUTHORITY_INFO_ACCESS in oids
        assert OID_CRL_DISTRIBUTION_POINTS in oids
        assert OID_AUTHORITY_KEY_IDENTIFIER not in oids

        for oid in set(oids):
            assert oids.count(oid) == 1, f"duplicate extension {oid}"

        assert der_encoder(tbs)

    def test_root_without_aia_crldp_in_csr_still_builds(self, issuer_key):
        bc = _make_basic_constraints_ext(ca=True, path_len=0)
        csr = _build_csr(issuer_key, "Bare Root", extensions=[bc])
        tbs = _build(None, csr, days=3650)
        assert _get_ext(tbs, OID_AUTHORITY_INFO_ACCESS) is None
        assert _get_ext(tbs, OID_CRL_DISTRIBUTION_POINTS) is None
        assert der_encoder(tbs)


class TestBuildRevokedCertificateEntry:

    def _make_time(self, dt: datetime) -> rfc5280.Time:
        from ca.crypto.util import get_ans1_time
        return get_ans1_time(dt)

    def test_serial_set(self):
        entry = build_revoked_certificate_entry(
            serial=rfc5280.CertificateSerialNumber(42),
            revocation_time=self._make_time(datetime(2025, 1, 1, tzinfo=timezone.utc)),
            revocation_reason=rfc5280.CRLReason("keyCompromise"),
        )
        assert int(entry["userCertificate"]) == 42

    def test_revocation_date_set(self):
        dt = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        entry = build_revoked_certificate_entry(
            serial=rfc5280.CertificateSerialNumber(1),
            revocation_time=self._make_time(dt),
            revocation_reason=rfc5280.CRLReason("unspecified"),
        )
        from ca.crypto.util import asn1_time_to_datetime
        assert asn1_time_to_datetime(entry["revocationDate"]) == dt

    @pytest.mark.parametrize(
        "reason",
        [
            "unspecified", "keyCompromise", "cACompromise", "affiliationChanged",
            "superseded", "cessationOfOperation", "certificateHold",
            "privilegeWithdrawn", "aACompromise",
        ],
    )
    def test_revocation_reason_encoded_correctly(self, reason):
        entry = build_revoked_certificate_entry(
            serial=rfc5280.CertificateSerialNumber(1),
            revocation_time=self._make_time(datetime(2025, 1, 1, tzinfo=timezone.utc)),
            revocation_reason=rfc5280.CRLReason(reason),
        )
        ext = next(e for e in entry["crlEntryExtensions"] if str(e["extnID"]) == OID_CRL_REASON)
        inner, _ = der_decoder(bytes(ext["extnValue"]), asn1Spec=rfc5280.CRLReason())
        assert str(inner) == reason

    def test_entry_is_der_encodable(self):
        entry = build_revoked_certificate_entry(
            serial=rfc5280.CertificateSerialNumber(1),
            revocation_time=self._make_time(datetime(2025, 1, 1, tzinfo=timezone.utc)),
            revocation_reason=rfc5280.CRLReason("keyCompromise"),
        )
        der = der_encoder(entry)
        decoded, _ = der_decoder(der, asn1Spec=RevokedCertificateEntry())
        assert int(decoded["userCertificate"]) == 1


class TestBuildTbsCertList:

    def _entry(self, serial: int):
        from ca.crypto.util import get_ans1_time
        return build_revoked_certificate_entry(
            serial=rfc5280.CertificateSerialNumber(serial),
            revocation_time=get_ans1_time(datetime(2025, 6, 1, tzinfo=timezone.utc)),
            revocation_reason=rfc5280.CRLReason("keyCompromise"),
        )

    def test_version_v2(self, issuer_cert):
        tbs = build_tbs_cert_list(
            issuer_cert=issuer_cert,
            days=7,
            signature_algorithm=get_algorithm_identifier(
                ec.generate_private_key(ec.SECP256R1()).public_key(), "SHA256"
            ),
            revoked_certificate_entries=[],
        )
        assert int(tbs["version"]) == CRL_VERSION  # v2 (encoded value 1)

    def test_issuer_from_issuer_cert(self, issuer_cert):
        tbs = build_tbs_cert_list(
            issuer_cert=issuer_cert,
            days=7,
            signature_algorithm=get_algorithm_identifier(
                ec.generate_private_key(ec.SECP256R1()).public_key(), "SHA256"
            ),
            revoked_certificate_entries=[],
        )
        assert der_encoder(tbs["issuer"]) == der_encoder(issuer_cert["tbsCertificate"]["subject"])

    def test_this_update_one_hour_before_now(self, issuer_cert):
        now = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        tbs = build_tbs_cert_list(
            issuer_cert=issuer_cert,
            days=7,
            signature_algorithm=get_algorithm_identifier(
                ec.generate_private_key(ec.SECP256R1()).public_key(), "SHA256"
            ),
            revoked_certificate_entries=[],
            now=now,
        )
        from ca.crypto.util import asn1_time_to_datetime
        assert asn1_time_to_datetime(tbs["thisUpdate"]) == now - timedelta(hours=1)

    def test_next_update_days_after_now(self, issuer_cert):
        now = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        tbs = build_tbs_cert_list(
            issuer_cert=issuer_cert,
            days=7,
            signature_algorithm=get_algorithm_identifier(
                ec.generate_private_key(ec.SECP256R1()).public_key(), "SHA256"
            ),
            revoked_certificate_entries=[],
            now=now,
        )
        from ca.crypto.util import asn1_time_to_datetime
        assert asn1_time_to_datetime(tbs["nextUpdate"]) == now + timedelta(days=7)

    def test_this_update_before_next_update(self, issuer_cert):
        tbs = build_tbs_cert_list(
            issuer_cert=issuer_cert,
            days=1,
            signature_algorithm=get_algorithm_identifier(
                ec.generate_private_key(ec.SECP256R1()).public_key(), "SHA256"
            ),
            revoked_certificate_entries=[],
        )
        from ca.crypto.util import asn1_time_to_datetime
        assert asn1_time_to_datetime(tbs["thisUpdate"]) < asn1_time_to_datetime(tbs["nextUpdate"])

    def test_revoked_entries_included(self, issuer_cert):
        entries = [self._entry(1), self._entry(2), self._entry(3)]
        tbs = build_tbs_cert_list(
            issuer_cert=issuer_cert,
            days=7,
            signature_algorithm=get_algorithm_identifier(
                ec.generate_private_key(ec.SECP256R1()).public_key(), "SHA256"
            ),
            revoked_certificate_entries=entries,
        )
        serials = sorted(int(e["userCertificate"]) for e in tbs["revokedCertificates"])
        assert serials == [1, 2, 3]

    def test_empty_revoked_list_is_valid(self, issuer_cert):
        """RFC 5280 §5.1.2.6: revokedCertificates is OPTIONAL — a CRL with
        no revoked certificates must still be valid and DER-encodable."""
        tbs = build_tbs_cert_list(
            issuer_cert=issuer_cert,
            days=7,
            signature_algorithm=get_algorithm_identifier(
                ec.generate_private_key(ec.SECP256R1()).public_key(), "SHA256"
            ),
            revoked_certificate_entries=[],
        )
        der = der_encoder(tbs)
        decoded, _ = der_decoder(der, asn1Spec=rfc5280.TBSCertList())
        assert int(decoded["version"]) == CRL_VERSION

    def test_signature_algorithm_set(self, issuer_cert):
        sig = get_algorithm_identifier(
            ec.generate_private_key(ec.SECP256R1()).public_key(), "SHA384"
        )
        tbs = build_tbs_cert_list(
            issuer_cert=issuer_cert, days=7, signature_algorithm=sig,
            revoked_certificate_entries=[],
        )
        assert der_encoder(tbs["signature"]) == der_encoder(sig)

    def test_tbs_crl_round_trips_with_revoked_entries(self, issuer_cert):
        entries = [self._entry(i) for i in (10, 20, 30)]
        tbs = build_tbs_cert_list(
            issuer_cert=issuer_cert,
            days=7,
            signature_algorithm=get_algorithm_identifier(
                ec.generate_private_key(ec.SECP256R1()).public_key(), "SHA256"
            ),
            revoked_certificate_entries=entries,
        )
        der = der_encoder(tbs)
        decoded, _ = der_decoder(der, asn1Spec=rfc5280.TBSCertList())
        decoded_serials = sorted(int(e["userCertificate"]) for e in decoded["revokedCertificates"])
        assert decoded_serials == [10, 20, 30]


def _wrap_as_cert(tbs: rfc5280.TBSCertificate) -> rfc5280.Certificate:
    sig_alg = tbs["signature"]
    cert = rfc5280.Certificate()
    cert["tbsCertificate"] = tbs
    cert["signatureAlgorithm"] = sig_alg
    cert["signature"] = univ.BitString(hexValue="00")
    return der_decoder(der_encoder(cert), asn1Spec=rfc5280.Certificate())[0]


def _ski_of(cert: rfc5280.Certificate) -> bytes:
    skid_ext = next(
        e for e in cert["tbsCertificate"]["extensions"]
        if str(e["extnID"]) == OID_SUBJECT_KEY_IDENTIFIER
    )
    decoded, _ = der_decoder(skid_ext["extnValue"], asn1Spec=rfc5280.SubjectKeyIdentifier())
    return bytes(decoded)


def _akid_of(tbs: rfc5280.TBSCertificate) -> bytes:
    akid_ext = next(
        e for e in tbs["extensions"]
        if str(e["extnID"]) == OID_AUTHORITY_KEY_IDENTIFIER
    )
    decoded, _ = der_decoder(akid_ext["extnValue"], asn1Spec=rfc5280.AuthorityKeyIdentifier())
    return bytes(decoded["keyIdentifier"])


class TestChainStructure:
    @pytest.fixture
    def chain(self):
        root_key = ec.generate_private_key(ec.SECP256R1())
        intermediate_key = ec.generate_private_key(ec.SECP256R1())
        leaf_key = ec.generate_private_key(ec.SECP256R1())

        root_aia = _make_aia_ext("http://ocsp.root.example.com")
        root_crldp = _make_crldp_ext("http://crl.root.example.com/root.crl")
        intermediate_aia = _make_aia_ext("http://ocsp.intermediate.example.com")
        intermediate_crldp = _make_crldp_ext("http://crl.intermediate.example.com/intermediate.crl")

        root_csr = _build_csr(
            root_key, "Root CA",
            extensions=[
                _make_basic_constraints_ext(ca=True, path_len=2),
                root_aia, root_crldp,
            ],
        )
        root_tbs = build_tbs_certificate(
            issuer_cert=None, csr=root_csr, days=3650,
            signature_algorithm=_sig_alg(),
        )
        root_cert = _wrap_as_cert(root_tbs)

        intermediate_csr = _build_csr(
            intermediate_key, "Intermediate CA",
            extensions=[
                _make_basic_constraints_ext(ca=True, path_len=0),
                intermediate_aia, intermediate_crldp,
            ],
        )
        intermediate_tbs = build_tbs_certificate(
            issuer_cert=root_cert, csr=intermediate_csr, days=1825,
            signature_algorithm=_sig_alg(),
        )
        intermediate_cert = _wrap_as_cert(intermediate_tbs)

        leaf_csr = _build_csr(
            leaf_key, "leaf.example.com",
            extensions=[_make_basic_constraints_ext(ca=False)],
        )
        leaf_tbs = build_tbs_certificate(
            issuer_cert=intermediate_cert, csr=leaf_csr, days=90,
            signature_algorithm=_sig_alg(),
            additional_extensions=[
                intermediate_aia, intermediate_crldp,
            ]
        )
        leaf_cert = _wrap_as_cert(leaf_tbs)

        return {
            "root_key": root_key, "root_cert": root_cert, "root_tbs": root_tbs,
            "intermediate_key": intermediate_key, "intermediate_cert": intermediate_cert,
            "intermediate_tbs": intermediate_tbs,
            "leaf_key": leaf_key, "leaf_cert": leaf_cert, "leaf_tbs": leaf_tbs,
            "root_aia": root_aia, "root_crldp": root_crldp,
            "intermediate_aia": intermediate_aia, "intermediate_crldp": intermediate_crldp,
        }

    def test_root_is_self_signed(self, chain):
        root = chain["root_cert"]["tbsCertificate"]
        assert der_encoder(root["issuer"]) == der_encoder(root["subject"])

    def test_intermediate_issuer_matches_root_subject(self, chain):
        intermediate = chain["intermediate_cert"]["tbsCertificate"]
        root = chain["root_cert"]["tbsCertificate"]
        assert der_encoder(intermediate["issuer"]) == der_encoder(root["subject"])

    def test_leaf_issuer_matches_intermediate_subject(self, chain):
        leaf = chain["leaf_cert"]["tbsCertificate"]
        intermediate = chain["intermediate_cert"]["tbsCertificate"]
        assert der_encoder(leaf["issuer"]) == der_encoder(intermediate["subject"])

    def test_chain_subjects_are_distinct(self, chain):
        subjects = {
            der_encoder(chain["root_cert"]["tbsCertificate"]["subject"]),
            der_encoder(chain["intermediate_cert"]["tbsCertificate"]["subject"]),
            der_encoder(chain["leaf_cert"]["tbsCertificate"]["subject"]),
        }
        assert len(subjects) == 3

    def test_root_has_no_akid(self, chain):
        oids = _all_ext_oids(chain["root_cert"]["tbsCertificate"])
        assert OID_AUTHORITY_KEY_IDENTIFIER not in oids

    def test_intermediate_akid_matches_root_ski(self, chain):
        assert _akid_of(chain["intermediate_tbs"]) == _ski_of(chain["root_cert"])

    def test_leaf_akid_matches_intermediate_ski(self, chain):
        assert _akid_of(chain["leaf_tbs"]) == _ski_of(chain["intermediate_cert"])

    def test_all_three_skis_are_distinct(self, chain):
        skis = {
            _ski_of(chain["root_cert"]),
            _ski_of(chain["intermediate_cert"]),
            _ski_of(chain["leaf_cert"]),
        }
        assert len(skis) == 3

    def test_leaf_spki_matches_leaf_csr(self, chain):
        cert_spki = der_encoder(chain["leaf_cert"]["tbsCertificate"]["subjectPublicKeyInfo"])
        leaf_pub = chain["leaf_key"].public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert cert_spki == leaf_pub

    def test_intermediate_spki_matches_intermediate_csr(self, chain):
        cert_spki = der_encoder(chain["intermediate_cert"]["tbsCertificate"]["subjectPublicKeyInfo"])
        intermediate_pub = chain["intermediate_key"].public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert cert_spki == intermediate_pub

    def test_intermediate_has_its_own_aia(self, chain):
        ext = next(
            e for e in chain["intermediate_tbs"]["extensions"]
            if str(e["extnID"]) == OID_AUTHORITY_INFO_ACCESS
        )
        assert bytes(ext["extnValue"]) == bytes(chain["intermediate_aia"]["extnValue"])

    def test_intermediate_has_its_own_crldp(self, chain):
        ext = next(
            e for e in chain["intermediate_tbs"]["extensions"]
            if str(e["extnID"]) == OID_CRL_DISTRIBUTION_POINTS
        )
        assert bytes(ext["extnValue"]) == bytes(chain["intermediate_crldp"]["extnValue"])

    def test_leaf_inherits_intermediate_aia(self, chain):
        ext = next(
            e for e in chain["leaf_tbs"]["extensions"]
            if str(e["extnID"]) == OID_AUTHORITY_INFO_ACCESS
        )
        assert bytes(ext["extnValue"]) == bytes(chain["intermediate_aia"]["extnValue"])

    def test_leaf_inherits_intermediate_crldp(self, chain):
        ext = next(
            e for e in chain["leaf_tbs"]["extensions"]
            if str(e["extnID"]) == OID_CRL_DISTRIBUTION_POINTS
        )
        assert bytes(ext["extnValue"]) == bytes(chain["intermediate_crldp"]["extnValue"])

    def test_leaf_does_not_inherit_root_aia(self, chain):
        ext = next(
            e for e in chain["leaf_tbs"]["extensions"]
            if str(e["extnID"]) == OID_AUTHORITY_INFO_ACCESS
        )
        assert bytes(ext["extnValue"]) != bytes(chain["root_aia"]["extnValue"])

    @pytest.mark.parametrize("cert_key", ["root_cert", "intermediate_cert", "leaf_cert"])
    def test_no_duplicate_extensions(self, chain, cert_key):
        oids = _all_ext_oids(chain[cert_key]["tbsCertificate"])
        duplicates = [o for o in set(oids) if oids.count(o) > 1]
        assert duplicates == []

    def test_root_is_ca_with_path_length(self, chain):
        ext = next(
            e for e in chain["root_cert"]["tbsCertificate"]["extensions"]
            if str(e["extnID"]) == OID_BASIC_CONSTRAINTS
        )
        bc, _ = der_decoder(ext["extnValue"], asn1Spec=rfc5280.BasicConstraints())
        assert bool(bc["cA"]) is True
        assert int(bc["pathLenConstraint"]) == 2

    def test_intermediate_is_ca_with_path_length_zero(self, chain):
        ext = next(
            e for e in chain["intermediate_cert"]["tbsCertificate"]["extensions"]
            if str(e["extnID"]) == OID_BASIC_CONSTRAINTS
        )
        bc, _ = der_decoder(ext["extnValue"], asn1Spec=rfc5280.BasicConstraints())
        assert bool(bc["cA"]) is True
        assert int(bc["pathLenConstraint"]) == 0

    def test_leaf_is_not_ca(self, chain):
        ext = next(
            e for e in chain["leaf_cert"]["tbsCertificate"]["extensions"]
            if str(e["extnID"]) == OID_BASIC_CONSTRAINTS
        )
        bc, _ = der_decoder(ext["extnValue"], asn1Spec=rfc5280.BasicConstraints())
        assert bool(bc["cA"]) is False

    def test_serial_numbers_distinct_across_chain(self, chain):
        serials = {
            int(chain["root_cert"]["tbsCertificate"]["serialNumber"]),
            int(chain["intermediate_cert"]["tbsCertificate"]["serialNumber"]),
            int(chain["leaf_cert"]["tbsCertificate"]["serialNumber"]),
        }
        assert len(serials) == 3

    @pytest.mark.parametrize("cert_key", ["root_cert", "intermediate_cert", "leaf_cert"])
    def test_each_cert_round_trips_through_der(self, chain, cert_key):
        der = der_encoder(chain[cert_key])
        decoded, _ = der_decoder(der, asn1Spec=rfc5280.Certificate())
        assert (
            int(decoded["tbsCertificate"]["serialNumber"])
            == int(chain[cert_key]["tbsCertificate"]["serialNumber"])
        )
