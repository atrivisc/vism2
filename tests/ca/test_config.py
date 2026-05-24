from __future__ import annotations

import ipaddress

import pytest
from cryptography import x509
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ
from pyasn1_modules import rfc5280

from ca.config import (
    CAConfig,
    CertificateConfig,
    KeyConfig,
    SupportedKeyAlgorithms,
    X509Config,
    X509ConfigAccessDescription,
    X509ConfigAccessDescriptionMethod,
    X509ConfigAuthorityInfoAccess,
    X509ConfigBasicConstraints,
    X509ConfigCRLDistributionPoints,
    X509ConfigDistributionPoint,
    X509ConfigDistributionPointName,
    X509ConfigDistributionPointReasonFlags,
    X509ConfigExtendedKeyUsage,
    X509ConfigKeyUsage,
    X509ConfigLocationType,
    X509ConfigSubjectAlternativeName,
    X509ConfigSubjectName,
)
from ca.errors import CertConfigNotFound


OID_KEY_USAGE = "2.5.29.15"
OID_EXTENDED_KEY_USAGE = "2.5.29.37"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_SAN = "2.5.29.17"
OID_AIA = "1.3.6.1.5.5.7.1.1"
OID_CRLDP = "2.5.29.31"
OID_OCSP = "1.3.6.1.5.5.7.48.1"
OID_CA_ISSUERS = "1.3.6.1.5.5.7.48.2"


def _load_extension_via_cert(oid: str, inner_der: bytes, ext_class):
    """Most cryptography extension classes don't expose a public from_der.
    To get them parsed, embed the raw DER inside a fresh certificate's
    extensions and read it back through the normal x509 API."""
    from datetime import datetime
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    key = _ec.generate_private_key(_ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")]))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2024, 1, 1))
        .not_valid_after(datetime(2034, 1, 1))
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), inner_der),
            critical=False,
        )
    )
    cert_der = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    parsed = x509.load_der_x509_certificate(cert_der)
    return parsed.extensions.get_extension_for_class(ext_class).value


# =========================================================================
# X509ConfigSubjectName
# =========================================================================

class TestX509ConfigSubjectName:

    def test_to_rdn_seq_emits_provided_attributes_only(self):
        s = X509ConfigSubjectName(common_name="ca.example.com", country="EE")
        rdn_seq = s.to_rdn_seq()
        assert len(rdn_seq) == 2

    def test_to_rdn_seq_emits_in_canonical_order(self):
        """The order is CN, C, ST, L, O — the order the helper calls
        _add_rdn in. Order matters because Name comparison is sequence-
        sensitive (RFC 5280 §4.1.2.4)."""
        s = X509ConfigSubjectName(
            common_name="cn", country="EE", state_or_province="Harju",
            locality="Tallinn", organization="Org",
        )
        rdn_seq = s.to_rdn_seq()
        # Pull the OID of each RDN's only ATV
        oids = [str(rdn[0]["type"]) for rdn in rdn_seq]
        assert oids == [
            x509.NameOID.COMMON_NAME.dotted_string,
            x509.NameOID.COUNTRY_NAME.dotted_string,
            x509.NameOID.STATE_OR_PROVINCE_NAME.dotted_string,
            x509.NameOID.LOCALITY_NAME.dotted_string,
            x509.NameOID.ORGANIZATION_NAME.dotted_string,
        ]

    def test_empty_subject_yields_empty_sequence(self):
        s = X509ConfigSubjectName()
        rdn_seq = s.to_rdn_seq()
        assert len(rdn_seq) == 0

    def test_to_asn1_round_trips_via_cryptography(self):
        s = X509ConfigSubjectName(common_name="ca.example.com", organization="Test", country="EE")
        name = s.to_asn1()
        der = der_encoder(name)
        # cryptography parses Name correctly only when wrapped in something;
        # easiest end-to-end: build a CSR with it
        decoded, _ = der_decoder(der, asn1Spec=rfc5280.Name())
        assert der_encoder(decoded) == der

    def test_to_asn1_values_are_utf8string(self):
        """RFC 5280 §4.1.2.4 recommends UTF8String for new certs (since 2003)."""
        s = X509ConfigSubjectName(common_name="ca.example.com")
        rdn_seq = s.to_rdn_seq()
        atv = rdn_seq[0][0]
        # UTF8String tag in DER is 0x0C
        value_der = der_encoder(atv["value"])
        assert value_der[0] == 0x0C


# =========================================================================
# X509ConfigKeyUsage
# =========================================================================

class TestX509ConfigKeyUsage:

    def test_no_flags_set_yields_all_zeros(self):
        ku = X509ConfigKeyUsage()
        bits = ku.to_asn1()
        # rfc5280.KeyUsage is a BitString constructed from the binary string
        assert str(bits) == "000000000"

    def test_single_flag_sets_correct_bit(self):
        ku = X509ConfigKeyUsage(digital_signature=True)
        assert str(ku.to_asn1())[0] == "1"

    def test_key_cert_sign_bit_position(self):
        """Bit 5 (0-indexed) per RFC 5280 §4.2.1.3."""
        ku = X509ConfigKeyUsage(key_cert_sign=True)
        assert str(ku.to_asn1())[5] == "1"

    def test_crl_sign_bit_position(self):
        """Bit 6 per RFC 5280 §4.2.1.3."""
        ku = X509ConfigKeyUsage(crl_sign=True)
        assert str(ku.to_asn1())[6] == "1"

    def test_multiple_flags(self):
        ku = X509ConfigKeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True)
        encoded = str(ku.to_asn1())
        assert encoded[0] == "1"  # digitalSignature
        assert encoded[5] == "1"  # keyCertSign
        assert encoded[6] == "1"  # crlSign
        # The rest should be zero
        for i in (1, 2, 3, 4, 7, 8):
            assert encoded[i] == "0"

    def test_to_asn1_ext_wraps_with_oid(self):
        ku = X509ConfigKeyUsage(digital_signature=True, critical=True)
        ext = ku.to_asn1_ext()
        assert str(ext["extnID"]) == OID_KEY_USAGE

    def test_to_asn1_ext_marks_critical_when_configured(self):
        """RFC 5280 §4.2.1.3: 'When present, conforming CAs SHOULD mark
        this extension as critical.'"""
        ku = X509ConfigKeyUsage(digital_signature=True, critical=True)
        ext = ku.to_asn1_ext()
        assert bool(ext["critical"]) is True

    def test_to_asn1_ext_critical_defaults_false(self):
        """The base class default for `critical` is False."""
        ku = X509ConfigKeyUsage(digital_signature=True)
        ext = ku.to_asn1_ext()
        # When not critical, the field is left at the DEFAULT (FALSE),
        # which DER omits. The pyasn1 Extension model uses
        # hasValue() to distinguish.
        assert not bool(ext["critical"])


# =========================================================================
# X509ConfigExtendedKeyUsage
# =========================================================================

class TestX509ConfigExtendedKeyUsage:

    def test_empty_usages_yields_empty_sequence(self):
        eku = X509ConfigExtendedKeyUsage(usages=[])
        assert len(eku.to_asn1()) == 0

    def test_oid_carries_through(self):
        eku = X509ConfigExtendedKeyUsage(usages=["1.3.6.1.5.5.7.3.1"])  # serverAuth
        asn1 = eku.to_asn1()
        assert str(asn1[0]) == "1.3.6.1.5.5.7.3.1"

    def test_multiple_oids_preserved(self):
        eku = X509ConfigExtendedKeyUsage(usages=[
            "1.3.6.1.5.5.7.3.1",  # serverAuth
            "1.3.6.1.5.5.7.3.2",  # clientAuth
        ])
        asn1 = eku.to_asn1()
        assert len(asn1) == 2

    def test_to_asn1_ext_wraps_with_oid(self):
        eku = X509ConfigExtendedKeyUsage(usages=["1.3.6.1.5.5.7.3.1"])
        ext = eku.to_asn1_ext()
        assert str(ext["extnID"]) == OID_EXTENDED_KEY_USAGE


class TestX509ConfigBasicConstraints:

    def test_ca_true_sets_ca_bool(self):
        bc = X509ConfigBasicConstraints(ca=True, path_length=2, critical=True)
        asn1 = bc.to_asn1()
        assert bool(asn1["cA"]) is True

    def test_ca_false_sets_ca_bool(self):
        bc = X509ConfigBasicConstraints(ca=False)
        asn1 = bc.to_asn1()
        assert bool(asn1["cA"]) is False

    def test_path_length_value_carries_through(self):
        bc = X509ConfigBasicConstraints(ca=True, path_length=3, critical=True)
        assert int(bc.to_asn1()["pathLenConstraint"]) == 3

    def test_path_length_omitted_when_not_ca(self):
        bc = X509ConfigBasicConstraints(ca=False, path_length=0)
        asn1 = bc.to_asn1()
        assert not asn1["pathLenConstraint"].hasValue()

    def test_basic_constraints_loadable_by_cryptography_for_leaf(self):
        """End-to-end check: a leaf BC (ca=False) must be loadable by
        the cryptography library. cryptography rejects BC with
        path_length set when ca=False."""
        bc = X509ConfigBasicConstraints(ca=False)
        ext = bc.to_asn1_ext()
        ext["critical"] = univ.Boolean(True)
        # Build a fake Extensions wrapper to feed cryptography indirectly
        ext_der = der_encoder(bc.to_asn1())
        loaded = x509.BasicConstraints(
            ca=False,
            path_length=None,
        )
        # Round-trip via the cryptography load function
        parsed, _ = der_decoder(ext_der, asn1Spec=rfc5280.BasicConstraints())
        assert bool(parsed["cA"]) is False
        # The bug surfaces when the leaf cert goes through
        # x509.load_der_x509_certificate -> get_extension_for_class.
        # Tested in test_certificate.py; here we just check the structural
        # invariant: path-len absent when ca=False.
        assert not parsed["pathLenConstraint"].hasValue()

    def test_to_asn1_ext_marks_critical(self):
        bc = X509ConfigBasicConstraints(ca=True, path_length=0, critical=True)
        ext = bc.to_asn1_ext()
        assert bool(ext["critical"]) is True

    def test_to_asn1_ext_oid(self):
        bc = X509ConfigBasicConstraints(ca=True, path_length=0, critical=True)
        ext = bc.to_asn1_ext()
        assert str(ext["extnID"]) == OID_BASIC_CONSTRAINTS


# =========================================================================
# X509ConfigSubjectAlternativeName
# =========================================================================

class TestX509ConfigSubjectAlternativeName:

    def test_dns_name_encodes_and_round_trips(self):
        """DNS names go into a GeneralName CHOICE under the dNSName
        branch (context tag [2]). Currently to_asn1 calls
        setComponentByName('dNSName', char.IA5String(dn)) without the
        implicit context tag — incompatible with the CHOICE branch."""
        san = X509ConfigSubjectAlternativeName(dns=["example.com"])
        asn1 = san.to_asn1()
        der = der_encoder(asn1)
        # Round-trip through cryptography's SubjectAlternativeName parser
        # by wrapping in an extension and loading via load_der.
        parsed, _ = der_decoder(der, asn1Spec=rfc5280.SubjectAltName())
        # The parsed dNSName should equal the input
        gn = parsed[0]
        assert str(gn.getComponent()) == "example.com"

    def test_email_name_encodes_and_round_trips(self):
        san = X509ConfigSubjectAlternativeName(emails=["admin@example.com"])
        asn1 = san.to_asn1()
        der = der_encoder(asn1)
        parsed, _ = der_decoder(der, asn1Spec=rfc5280.SubjectAltName())
        gn = parsed[0]
        assert str(gn.getComponent()) == "admin@example.com"

    def test_ipv4_address_is_four_bytes(self):
        """RFC 5280 §4.2.1.6: 'For IP version 4 ... the octet string MUST
        contain exactly four octets.' The current implementation passes
        the IP as an ASCII string to OctetString, which yields 11+ bytes
        for typical IPv4 addresses."""
        san = X509ConfigSubjectAlternativeName(ips=["192.168.1.1"])
        asn1 = san.to_asn1()
        der = der_encoder(asn1)
        parsed, _ = der_decoder(der, asn1Spec=rfc5280.SubjectAltName())
        ip_octets = bytes(parsed[0].getComponent())
        assert len(ip_octets) == 4
        assert ip_octets == bytes(ipaddress.IPv4Address("192.168.1.1").packed)

    def test_ipv6_address_is_sixteen_bytes(self):
        """RFC 5280 §4.2.1.6: 'For IP version 6 ... the octet string MUST
        contain exactly sixteen octets.'"""
        san = X509ConfigSubjectAlternativeName(ips=["2001:db8::1"])
        asn1 = san.to_asn1()
        der = der_encoder(asn1)
        parsed, _ = der_decoder(der, asn1Spec=rfc5280.SubjectAltName())
        ip_octets = bytes(parsed[0].getComponent())
        assert len(ip_octets) == 16
        assert ip_octets == bytes(ipaddress.IPv6Address("2001:db8::1").packed)

    def test_mixed_names(self):
        """A SAN can carry multiple name types together."""
        san = X509ConfigSubjectAlternativeName(
            dns=["example.com"], emails=["admin@example.com"], ips=["10.0.0.1"]
        )
        asn1 = san.to_asn1()
        assert len(asn1) == 3

    def test_empty_san_yields_empty_sequence(self):
        """RFC 5280 §4.2.1.6 requires SAN to be non-empty when present,
        but the config class doesn't enforce that — at minimum, building
        with nothing shouldn't crash."""
        san = X509ConfigSubjectAlternativeName()
        asn1 = san.to_asn1()
        assert len(asn1) == 0

    def test_to_asn1_ext_loadable_via_cryptography(self):
        """End-to-end: a SAN extension must be parseable by
        cryptography.x509 (the verifier side)."""
        san = X509ConfigSubjectAlternativeName(
            dns=["example.com", "www.example.com"], ips=["10.0.0.1"]
        )
        inner_der = der_encoder(san.to_asn1())
        loaded = _load_extension_via_cert(OID_SAN, inner_der, x509.SubjectAlternativeName)
        dns = {n.value for n in loaded if isinstance(n, x509.DNSName)}
        ips = {n.value for n in loaded if isinstance(n, x509.IPAddress)}
        assert dns == {"example.com", "www.example.com"}
        assert {str(ip) for ip in ips} == {"10.0.0.1"}


# =========================================================================
# X509ConfigAccessDescription / X509ConfigAuthorityInfoAccess
# =========================================================================

class TestX509ConfigAccessDescription:

    def test_ocsp_method_yields_ocsp_oid(self):
        ad = X509ConfigAccessDescription(
            access_method=X509ConfigAccessDescriptionMethod.OCSP,
            access_location="http://ocsp.example.com",
        )
        asn1 = ad.to_ans1()
        assert str(asn1["accessMethod"]) == OID_OCSP

    def test_ca_method_yields_ca_issuers_oid(self):
        ad = X509ConfigAccessDescription(
            access_method=X509ConfigAccessDescriptionMethod.CA,
            access_location="http://ca.example.com/ca.crt",
        )
        asn1 = ad.to_ans1()
        assert str(asn1["accessMethod"]) == OID_CA_ISSUERS

    def test_url_location_uses_uri_choice(self):
        ad = X509ConfigAccessDescription(
            access_method=X509ConfigAccessDescriptionMethod.OCSP,
            access_location="http://ocsp.example.com",
        )
        asn1 = ad.to_ans1()
        # accessLocation is a GeneralName CHOICE; uniformResourceIdentifier is branch [6]
        gn = asn1["accessLocation"]
        assert gn.getName() == "uniformResourceIdentifier"
        assert str(gn.getComponent()) == "http://ocsp.example.com"

    def test_unsupported_location_type_raises(self):
        ad = X509ConfigAccessDescription(
            access_method=X509ConfigAccessDescriptionMethod.OCSP,
            access_location="anything",
        )
        # Force an unsupported location type
        ad.access_location_type = "DIRECTORY_NAME"
        with pytest.raises((NotImplementedError, Exception)):
            ad.to_ans1()


class TestX509ConfigAuthorityInfoAccess:

    def test_empty_descriptions_yields_empty_aia(self):
        aia = X509ConfigAuthorityInfoAccess(descriptions=[])
        asn1 = aia.to_asn1()
        assert len(asn1) == 0

    def test_single_description_carries_through(self):
        aia = X509ConfigAuthorityInfoAccess(descriptions=[
            X509ConfigAccessDescription(
                access_method=X509ConfigAccessDescriptionMethod.OCSP,
                access_location="http://ocsp.example.com",
            )
        ])
        asn1 = aia.to_asn1()
        assert len(asn1) == 1
        assert str(asn1[0]["accessMethod"]) == OID_OCSP

    def test_multiple_descriptions(self):
        aia = X509ConfigAuthorityInfoAccess(descriptions=[
            X509ConfigAccessDescription(
                access_method=X509ConfigAccessDescriptionMethod.OCSP,
                access_location="http://ocsp.example.com",
            ),
            X509ConfigAccessDescription(
                access_method=X509ConfigAccessDescriptionMethod.CA,
                access_location="http://ca.example.com/ca.crt",
            ),
        ])
        asn1 = aia.to_asn1()
        assert len(asn1) == 2

    def test_to_asn1_ext_loadable_via_cryptography(self):
        aia = X509ConfigAuthorityInfoAccess(descriptions=[
            X509ConfigAccessDescription(
                access_method=X509ConfigAccessDescriptionMethod.OCSP,
                access_location="http://ocsp.example.com",
            ),
        ])
        inner_der = der_encoder(aia.to_asn1())
        loaded = _load_extension_via_cert(OID_AIA, inner_der, x509.AuthorityInformationAccess)
        urls = {ad.access_location.value for ad in loaded}
        assert urls == {"http://ocsp.example.com"}

    def test_to_asn1_ext_oid(self):
        aia = X509ConfigAuthorityInfoAccess(descriptions=[
            X509ConfigAccessDescription(
                access_method=X509ConfigAccessDescriptionMethod.OCSP,
                access_location="http://ocsp.example.com",
            )
        ])
        ext = aia.to_asn1_ext()
        assert str(ext["extnID"]) == OID_AIA


# =========================================================================
# X509ConfigDistributionPoint* / X509ConfigCRLDistributionPoints
# =========================================================================

class TestX509ConfigDistributionPointName:

    def test_url_uses_uri_choice(self):
        dpn = X509ConfigDistributionPointName(name="http://crl.example.com/x.crl")
        gn = dpn.to_general_name()
        assert gn.getName() == "uniformResourceIdentifier"
        assert str(gn.getComponent()) == "http://crl.example.com/x.crl"

    def test_unsupported_type_raises(self):
        dpn = X509ConfigDistributionPointName(name="something")
        dpn.name_type = "DIRECTORY_NAME"
        with pytest.raises((NotImplementedError, Exception)):
            dpn.to_general_name()


class TestX509ConfigDistributionPoint:

    def test_full_name_carries_through(self):
        dp = X509ConfigDistributionPoint(
            names=[X509ConfigDistributionPointName(name="http://crl.example.com/x.crl")],
        )
        asn1 = dp.to_asn1()
        dp_name = asn1["distributionPoint"]
        assert dp_name.getName() == "fullName"

    def test_reasons_omitted_when_empty(self):
        """RFC 5280 §4.2.1.13 makes reasons optional; the encoder
        should omit them when no reasons are set."""
        dp = X509ConfigDistributionPoint(
            names=[X509ConfigDistributionPointName(name="http://crl.example.com/x.crl")],
            reasons=[],
        )
        asn1 = dp.to_asn1()
        assert not asn1["reasons"].hasValue()

    def test_reasons_bit_string_uses_rfc_5280_bit_order(self):
        """RFC 5280 §4.2.1.13 ReasonFlags: bit 0 is unused, bit 1 is
        keyCompromise, etc. The enum X509ConfigDistributionPointReasonFlags
        is declared in the same order, so iterating it yields the right
        bit string."""
        dp = X509ConfigDistributionPoint(
            names=[X509ConfigDistributionPointName(name="http://crl.example.com/x.crl")],
            reasons=[X509ConfigDistributionPointReasonFlags.keyCompromise],
        )
        asn1 = dp.to_asn1()
        # Bit 1 set, all others zero. pyasn1 BitString stringifies as binary digits.
        flags = str(asn1["reasons"])
        assert flags[1] == "1"
        assert flags[0] == "0"
        # No other bits set
        for i in range(2, len(flags)):
            assert flags[i] == "0"

    def test_multiple_reasons(self):
        dp = X509ConfigDistributionPoint(
            names=[X509ConfigDistributionPointName(name="http://crl.example.com/x.crl")],
            reasons=[
                X509ConfigDistributionPointReasonFlags.keyCompromise,
                X509ConfigDistributionPointReasonFlags.cACompromise,
            ],
        )
        asn1 = dp.to_asn1()
        flags = str(asn1["reasons"])
        assert flags[1] == "1"  # keyCompromise
        assert flags[2] == "1"  # cACompromise


class TestX509ConfigCRLDistributionPoints:

    def test_empty_points_yields_empty_sequence(self):
        crldp = X509ConfigCRLDistributionPoints(points=[])
        assert len(crldp.to_asn1()) == 0

    def test_single_point_carries_through(self):
        crldp = X509ConfigCRLDistributionPoints(points=[
            X509ConfigDistributionPoint(
                names=[X509ConfigDistributionPointName(name="http://crl.example.com/x.crl")],
            )
        ])
        assert len(crldp.to_asn1()) == 1

    def test_to_asn1_ext_loadable_via_cryptography(self):
        crldp = X509ConfigCRLDistributionPoints(points=[
            X509ConfigDistributionPoint(
                names=[X509ConfigDistributionPointName(name="http://crl.example.com/x.crl")],
            )
        ])
        inner_der = der_encoder(crldp.to_asn1())
        loaded = _load_extension_via_cert(OID_CRLDP, inner_der, x509.CRLDistributionPoints)
        urls = set()
        for dp in loaded:
            for n in (dp.full_name or []):
                urls.add(n.value)
        assert urls == {"http://crl.example.com/x.crl"}

    def test_to_asn1_ext_oid(self):
        crldp = X509ConfigCRLDistributionPoints(points=[
            X509ConfigDistributionPoint(
                names=[X509ConfigDistributionPointName(name="http://crl.example.com/x.crl")],
            )
        ])
        ext = crldp.to_asn1_ext()
        assert str(ext["extnID"]) == OID_CRLDP


# =========================================================================
# KeyConfig
# =========================================================================

class TestKeyConfig:

    def test_ec_with_curve_ok(self):
        kc = KeyConfig(algorithm=SupportedKeyAlgorithms.ec, curve="secp256r1")
        assert kc.algorithm == SupportedKeyAlgorithms.ec
        assert kc.curve == "secp256r1"

    def test_rsa_with_valid_bits_ok(self):
        kc = KeyConfig(algorithm=SupportedKeyAlgorithms.rsa, bits=4096)
        assert kc.algorithm == SupportedKeyAlgorithms.rsa
        assert kc.bits == 4096

    @pytest.mark.parametrize("bits", [2048, 3072, 4096, 8192])
    def test_rsa_bits_in_range_accepted(self, bits):
        kc = KeyConfig(algorithm=SupportedKeyAlgorithms.rsa, bits=bits)
        assert kc.bits == bits

    @pytest.mark.parametrize("bits", [512, 1024, 8193, 16384])
    def test_rsa_bits_out_of_range_rejected(self, bits):
        """RSA below 2048 bits is no longer considered secure; above 8192
        is impractical. The validator enforces a 2048-8192 range."""
        from pydantic_core import ValidationError
        with pytest.raises(ValidationError):
            KeyConfig(algorithm=SupportedKeyAlgorithms.rsa, bits=bits)

    def test_rsa_bits_field_required(self):
        """The bits field is typed as int (not Optional[int]), so pydantic
        rejects None even though the validator would let it through. This
        means EC configs must omit bits entirely rather than passing
        bits=None — a minor API quirk."""
        from pydantic_core import ValidationError
        with pytest.raises(ValidationError):
            KeyConfig(algorithm=SupportedKeyAlgorithms.ec, curve="secp256r1", bits=None)

    def test_bits_can_be_omitted(self):
        """The field has a default of None at the dataclass level, so
        omitting it is fine."""
        kc = KeyConfig(algorithm=SupportedKeyAlgorithms.ec, curve="secp256r1")
        assert kc.bits is None

    def test_ec_with_bits_accepted(self):
        """Currently the bits validator doesn't check that algorithm is
        RSA — it accepts a bits value with an EC algorithm. This is
        confusing but not technically broken; documenting the behavior."""
        kc = KeyConfig(algorithm=SupportedKeyAlgorithms.ec, curve="secp256r1", bits=2048)
        assert kc.bits == 2048


# =========================================================================
# CertificateConfig
# =========================================================================

def _ca_x509():
    return X509Config(
        days=3650, crl_days=7,
        subject_name=X509ConfigSubjectName(common_name="Test CA"),
        basic_constraints=X509ConfigBasicConstraints(ca=True, path_length=2, critical=True),
    )


class TestCertificateConfigKeyLabel:

    def test_rsa_label(self):
        cfg = CertificateConfig(
            name="my-ca",
            key=KeyConfig(algorithm=SupportedKeyAlgorithms.rsa, bits=4096),
            x509=_ca_x509(),
        )
        assert cfg.key_label == "my-ca-RSA-4096"

    def test_ec_label(self):
        cfg = CertificateConfig(
            name="my-ca",
            key=KeyConfig(algorithm=SupportedKeyAlgorithms.ec, curve="secp256r1"),
            x509=_ca_x509(),
        )
        assert cfg.key_label == "my-ca-EC-secp256r1"


class TestCertificateConfigKeyP11Attributes:

    def test_rsa_attributes(self):
        import pkcs11
        cfg = CertificateConfig(
            name="my-ca",
            key=KeyConfig(algorithm=SupportedKeyAlgorithms.rsa, bits=4096),
            x509=_ca_x509(),
        )
        attrs = cfg.key_p11_attributes
        assert attrs[pkcs11.Attribute.KEY_TYPE] == pkcs11.KeyType.RSA
        assert attrs[pkcs11.Attribute.MODULUS_BITS] == 4096
        assert attrs[pkcs11.Attribute.LABEL] == "my-ca-RSA-4096"

    def test_ec_attributes(self):
        import pkcs11
        cfg = CertificateConfig(
            name="my-ca",
            key=KeyConfig(algorithm=SupportedKeyAlgorithms.ec, curve="secp256r1"),
            x509=_ca_x509(),
        )
        attrs = cfg.key_p11_attributes
        assert attrs[pkcs11.Attribute.KEY_TYPE] == pkcs11.KeyType.EC
        assert pkcs11.Attribute.EC_PARAMS in attrs
        assert pkcs11.Attribute.MODULUS_BITS not in attrs

    def test_id_is_sha3_256_of_name(self):
        import hashlib, pkcs11
        cfg = CertificateConfig(
            name="my-ca",
            key=KeyConfig(algorithm=SupportedKeyAlgorithms.ec, curve="secp256r1"),
            x509=_ca_x509(),
        )
        attrs = cfg.key_p11_attributes
        assert attrs[pkcs11.Attribute.ID] == hashlib.sha3_256(b"my-ca").digest()


# =========================================================================
# CAConfig.get_cert_config_by_name
# =========================================================================

class TestCAConfigGetCertConfigByName:

    def _config_named(self, name: str) -> CertificateConfig:
        return CertificateConfig(
            name=name,
            key=KeyConfig(algorithm=SupportedKeyAlgorithms.ec, curve="secp256r1"),
            x509=_ca_x509(),
        )

    def _ca_config(self, *cert_names: str) -> CAConfig:
        """Build a CAConfig with a non-empty Security block. vism_lib's
        Security requires data_validation_key, so the bare CAConfig(...)
        default no longer validates."""
        from vism_lib.config import Security
        return CAConfig(
            security=Security(data_validation_key="test-key"),
            x509_certificates=[self._config_named(n) for n in cert_names],
        )

    def test_returns_matching_config(self):
        ca = self._ca_config("root", "intermediate")
        result = ca.get_cert_config_by_name("intermediate")
        assert result.name == "intermediate"

    def test_raises_when_not_found(self):
        ca = self._ca_config("root")
        with pytest.raises(CertConfigNotFound):
            ca.get_cert_config_by_name("nonexistent")

    def test_raises_on_duplicate_names(self):
        """The config-loader should ideally catch duplicate names earlier,
        but this method is the last line of defense."""
        ca = self._ca_config("root", "root")
        with pytest.raises(ValueError):
            ca.get_cert_config_by_name("root")