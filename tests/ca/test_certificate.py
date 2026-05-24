from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ
from pyasn1_modules import rfc2986, rfc5280

from ca.certificate import CertificateManager
from ca.config import (
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
    X509ConfigKeyUsage,
    X509ConfigSubjectName,
)
from ca.database import IssuedCertificate
from vism_lib.errors import VismBreakingException

from tests.ca._helpers import (
    LocalKeyManager,
    LocalPrivKey,
    LocalPubKey,
    make_external_leaf_csr as _make_external_leaf_csr,
)


OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14"
OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1"
OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31"


# =========================================================================
# Config helpers
# =========================================================================

def _subject(cn: str, country: str = "EE", organization: str = "Test Org") -> X509ConfigSubjectName:
    return X509ConfigSubjectName(
        common_name=cn, country=country, organization=organization
    )


def _aia(url: str = "http://ocsp.example.com") -> X509ConfigAuthorityInfoAccess:
    return X509ConfigAuthorityInfoAccess(
        descriptions=[
            X509ConfigAccessDescription(
                access_method=X509ConfigAccessDescriptionMethod.OCSP,
                access_location=url,
            )
        ]
    )


def _crldp(url: str = "http://crl.example.com/x.crl") -> X509ConfigCRLDistributionPoints:
    return X509ConfigCRLDistributionPoints(
        points=[
            X509ConfigDistributionPoint(
                names=[X509ConfigDistributionPointName(name=url)]
            )
        ]
    )


def _ca_x509_config(
    cn: str,
    *,
    path_length: int = 0,
    aia_url: str | None = "http://ocsp.example.com",
    crl_url: str | None = "http://crl.example.com/x.crl",
    days: int = 365,
    crl_days: int = 7,
) -> X509Config:
    kwargs = dict(
        days=days, crl_days=crl_days,
        subject_name=_subject(cn),
        basic_constraints=X509ConfigBasicConstraints(ca=True, path_length=path_length, critical=True),
        key_usage=X509ConfigKeyUsage(
            key_cert_sign=True, crl_sign=True, digital_signature=True, critical=True
        ),
    )
    if aia_url:
        kwargs["authority_info_access"] = _aia(aia_url)
    if crl_url:
        kwargs["crl_distribution_points"] = _crldp(crl_url)
    return X509Config(**kwargs)


def _cert_config(name: str, x509_cfg: X509Config) -> CertificateConfig:
    return CertificateConfig(
        name=name,
        key=KeyConfig(algorithm=SupportedKeyAlgorithms.ec, curve="secp256r1"),
        x509=x509_cfg,
    )


def _make_manager(name: str, x509_cfg: X509Config, key: ec.EllipticCurvePrivateKey) -> CertificateManager:
    privkey = LocalPrivKey(key, label=f"{name}-priv")
    pubkey = LocalPubKey(key.public_key(), label=f"{name}-pub")
    return CertificateManager(
        key_manager=LocalKeyManager(),
        privkey=privkey,
        pubkey=pubkey,
        config=_cert_config(name, x509_cfg),
    )


def _crypto_cert(asn1_cert: rfc5280.Certificate) -> x509.Certificate:
    return x509.load_der_x509_certificate(der_encoder(asn1_cert))


def _get_ext_in_tbs(tbs: rfc5280.TBSCertificate, oid: str) -> rfc5280.Extension | None:
    for ext in tbs["extensions"]:
        if str(ext["extnID"]) == oid:
            return ext
    return None


@pytest.fixture
def root_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def intermediate_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def leaf_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def root_manager(root_key) -> CertificateManager:
    return _make_manager("root", _ca_x509_config("Test Root CA", path_length=2), root_key)


@pytest.fixture
def intermediate_manager(intermediate_key) -> CertificateManager:
    cfg = _ca_x509_config(
        "Test Intermediate CA",
        path_length=0,
        aia_url="http://ocsp.intermediate.example.com",
        crl_url="http://crl.intermediate.example.com/intermediate.crl",
    )
    return _make_manager("intermediate", cfg, intermediate_key)


class TestCertificateManagerInit:

    def test_loads_der_public_key(self, root_key):
        privkey = LocalPrivKey(root_key)
        pubkey = LocalPubKey(root_key.public_key())
        mgr = CertificateManager(
            key_manager=LocalKeyManager(),
            privkey=privkey,
            pubkey=pubkey,
            config=_cert_config("root", _ca_x509_config("Root")),
        )
        assert isinstance(mgr.public_key, ec.EllipticCurvePublicKey)

    def test_falls_back_to_pem_loader(self, root_key):
        class PemPubKey(LocalPubKey):
            def public_bytes(self) -> bytes:
                return self._crypto_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )

        privkey = LocalPrivKey(root_key)
        pubkey = PemPubKey(root_key.public_key())
        mgr = CertificateManager(
            key_manager=LocalKeyManager(),
            privkey=privkey,
            pubkey=pubkey,
            config=_cert_config("root", _ca_x509_config("Root")),
        )
        assert isinstance(mgr.public_key, ec.EllipticCurvePublicKey)

    def test_externally_managed_requires_cert_and_crl(self, root_key):
        cfg = _cert_config("ext", _ca_x509_config("External"))
        cfg.externally_managed = True
        with pytest.raises(VismBreakingException):
            CertificateManager(
                key_manager=LocalKeyManager(),
                privkey=LocalPrivKey(root_key),
                pubkey=LocalPubKey(root_key.public_key()),
                config=cfg,
            )

    def test_externally_managed_with_both_pems_ok(self, root_key):
        cfg = _cert_config("ext", _ca_x509_config("External"))
        cfg.externally_managed = True
        cfg.certificate_pem = "dummy"
        cfg.crl_pem = "dummy"
        mgr = CertificateManager(
            key_manager=LocalKeyManager(),
            privkey=LocalPrivKey(root_key),
            pubkey=LocalPubKey(root_key.public_key()),
            config=cfg,
        )
        assert mgr.config.externally_managed is True


class TestCreateCsr:

    def test_returns_certification_request(self, root_manager):
        csr = root_manager.create_csr()
        assert isinstance(csr, rfc2986.CertificationRequest)

    def test_csr_subject_matches_config(self, root_manager):
        csr = root_manager.create_csr()
        expected = root_manager.config.x509.subject_name.to_asn1()
        actual = csr["certificationRequestInfo"]["subject"]
        assert der_encoder(actual) == der_encoder(expected)

    def test_csr_spki_matches_public_key(self, root_manager, root_key):
        csr = root_manager.create_csr()
        spki_der = der_encoder(csr["certificationRequestInfo"]["subjectPKInfo"])
        expected = root_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert spki_der == expected

    def test_csr_round_trips_through_der(self, root_manager):
        csr = root_manager.create_csr()
        der = der_encoder(csr)
        decoded, _ = der_decoder(der, asn1Spec=rfc2986.CertificationRequest())
        assert int(decoded["certificationRequestInfo"]["version"]) == 0

    def test_csr_signature_verifies(self, root_manager, root_key):
        csr_asn1 = root_manager.create_csr()
        csr_der = der_encoder(csr_asn1)
        csr = x509.load_der_x509_csr(csr_der)
        assert csr.is_signature_valid

    def test_csr_includes_configured_extensions(self, root_manager):
        csr_asn1 = root_manager.create_csr()
        csr_der = der_encoder(csr_asn1)
        csr = x509.load_der_x509_csr(csr_der)
        ext_oids = {ext.oid.dotted_string for ext in csr.extensions}
        assert OID_BASIC_CONSTRAINTS in ext_oids
        assert OID_KEY_USAGE in ext_oids
        assert OID_AUTHORITY_INFO_ACCESS in ext_oids
        assert OID_CRL_DISTRIBUTION_POINTS in ext_oids

    def test_csr_omits_unconfigured_extensions(self, root_key):
        cfg = _ca_x509_config("CSR Test CA", aia_url=None, crl_url=None)
        mgr = _make_manager("csr-test", cfg, root_key)
        csr_asn1 = mgr.create_csr()
        csr_der = der_encoder(csr_asn1)
        csr = x509.load_der_x509_csr(csr_der)
        ext_oids = {ext.oid.dotted_string for ext in csr.extensions}
        assert OID_AUTHORITY_INFO_ACCESS not in ext_oids
        assert OID_CRL_DISTRIBUTION_POINTS not in ext_oids
        assert OID_BASIC_CONSTRAINTS in ext_oids
        assert OID_KEY_USAGE in ext_oids


class TestSignCsrSelfSignedRoot:

    def test_returns_certificate(self, root_manager):
        csr = root_manager.create_csr()
        crt = root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)
        assert isinstance(crt, rfc5280.Certificate)

    def test_self_signed_signature_verifies(self, root_manager):
        csr = root_manager.create_csr()
        crt_asn1 = root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)
        crt = _crypto_cert(crt_asn1)
        crt.verify_directly_issued_by(crt)

    def test_root_has_no_aki(self, root_manager):
        csr = root_manager.create_csr()
        crt = root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)
        assert _get_ext_in_tbs(crt["tbsCertificate"], OID_AUTHORITY_KEY_IDENTIFIER) is None

    def test_root_has_aia_from_csr(self, root_manager):
        csr = root_manager.create_csr()
        crt = root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)
        assert _get_ext_in_tbs(crt["tbsCertificate"], OID_AUTHORITY_INFO_ACCESS) is not None

    def test_root_has_crldp_from_csr(self, root_manager):
        csr = root_manager.create_csr()
        crt = root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)
        assert _get_ext_in_tbs(crt["tbsCertificate"], OID_CRL_DISTRIBUTION_POINTS) is not None

    def test_root_subject_equals_issuer(self, root_manager):
        csr = root_manager.create_csr()
        crt = root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)
        tbs = crt["tbsCertificate"]
        assert der_encoder(tbs["subject"]) == der_encoder(tbs["issuer"])

    def test_no_duplicate_extensions(self, root_manager):
        csr = root_manager.create_csr()
        crt = root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)
        oids = [str(e["extnID"]) for e in crt["tbsCertificate"]["extensions"]]
        assert len(oids) == len(set(oids))

    def test_basic_constraints_is_ca_true(self, root_manager):
        csr = root_manager.create_csr()
        crt = root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)
        crypto_crt = _crypto_cert(crt)
        bc = crypto_crt.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True

    def test_signature_algorithm_in_outer_matches_tbs(self, root_manager):
        csr = root_manager.create_csr()
        crt = root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)
        assert der_encoder(crt["signatureAlgorithm"]) == der_encoder(crt["tbsCertificate"]["signature"])


class TestSignCsrIntermediate:

    @pytest.fixture
    def signed_root(self, root_manager) -> rfc5280.Certificate:
        csr = root_manager.create_csr()
        return root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)

    def test_signature_verifies_against_root(self, root_manager, intermediate_manager, signed_root):
        csr = intermediate_manager.create_csr()
        crt_asn1 = root_manager.sign_csr(signer=signed_root, csr=csr, days=1825, is_ca=True)
        crt = _crypto_cert(crt_asn1)
        root_crypto = _crypto_cert(signed_root)
        crt.verify_directly_issued_by(root_crypto)

    def test_issuer_is_root_subject(self, root_manager, intermediate_manager, signed_root):
        csr = intermediate_manager.create_csr()
        crt = root_manager.sign_csr(signer=signed_root, csr=csr, days=1825, is_ca=True)
        assert der_encoder(crt["tbsCertificate"]["issuer"]) == der_encoder(signed_root["tbsCertificate"]["subject"])

    def test_subject_is_intermediate_csr_subject(self, root_manager, intermediate_manager, signed_root):
        csr = intermediate_manager.create_csr()
        crt = root_manager.sign_csr(signer=signed_root, csr=csr, days=1825, is_ca=True)
        assert der_encoder(crt["tbsCertificate"]["subject"]) == der_encoder(
            csr["certificationRequestInfo"]["subject"]
        )

    def test_has_aki(self, root_manager, intermediate_manager, signed_root):
        csr = intermediate_manager.create_csr()
        crt = root_manager.sign_csr(signer=signed_root, csr=csr, days=1825, is_ca=True)
        crypto_crt = _crypto_cert(crt)
        aki = crypto_crt.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        assert aki is not None

    def test_aki_matches_root_ski(self, root_manager, intermediate_manager, signed_root):
        csr = intermediate_manager.create_csr()
        crt = root_manager.sign_csr(signer=signed_root, csr=csr, days=1825, is_ca=True)
        crypto_crt = _crypto_cert(crt)
        root_crypto = _crypto_cert(signed_root)

        aki = crypto_crt.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        ski = root_crypto.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        assert aki.key_identifier == ski.key_identifier

    def test_intermediate_has_its_own_aia_not_roots(self, root_manager, intermediate_manager, signed_root):
        csr = intermediate_manager.create_csr()
        crt = root_manager.sign_csr(signer=signed_root, csr=csr, days=1825, is_ca=True)
        crypto_crt = _crypto_cert(crt)
        aia = crypto_crt.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        urls = {ad.access_location.value for ad in aia}
        # intermediate config URL contains "intermediate"
        assert any("intermediate" in u for u in urls)

    def test_no_duplicate_extensions(self, root_manager, intermediate_manager, signed_root):
        csr = intermediate_manager.create_csr()
        crt = root_manager.sign_csr(signer=signed_root, csr=csr, days=1825, is_ca=True)
        oids = [str(e["extnID"]) for e in crt["tbsCertificate"]["extensions"]]
        assert len(oids) == len(set(oids))


class TestSignCsrLeaf:
    @pytest.fixture
    def chain(self, root_manager, intermediate_manager):
        root_csr = root_manager.create_csr()
        root_cert = root_manager.sign_csr(signer=None, csr=root_csr, days=3650, is_ca=True)
        intermediate_csr = intermediate_manager.create_csr()
        intermediate_cert = root_manager.sign_csr(
            signer=root_cert, csr=intermediate_csr, days=1825, is_ca=True
        )
        return {"root": root_cert, "intermediate": intermediate_cert}

    def test_signature_verifies_against_intermediate(self, intermediate_manager, leaf_key, chain):
        csr = _make_external_leaf_csr(leaf_key, "leaf.example.com")
        crt_asn1 = intermediate_manager.sign_csr(
            signer=chain["intermediate"], csr=csr, days=90, is_ca=False
        )
        crt = _crypto_cert(crt_asn1)
        intermediate_crypto = _crypto_cert(chain["intermediate"])
        crt.verify_directly_issued_by(intermediate_crypto)

    def test_leaf_is_not_a_ca(self, intermediate_manager, leaf_key, chain):
        csr = _make_external_leaf_csr(leaf_key, "leaf.example.com")
        crt = intermediate_manager.sign_csr(
            signer=chain["intermediate"], csr=csr, days=90, is_ca=False
        )
        crypto_crt = _crypto_cert(crt)
        bc = crypto_crt.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_leaf_inherits_crldp_from_intermediate_cert(self, intermediate_manager, leaf_key, chain):
        csr = _make_external_leaf_csr(leaf_key, "leaf.example.com")
        crt = intermediate_manager.sign_csr(
            signer=chain["intermediate"], csr=csr, days=90, is_ca=False
        )
        crypto_crt = _crypto_cert(crt)
        crldp = crypto_crt.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        urls = set()
        for dp in crldp:
            if dp.full_name:
                for n in dp.full_name:
                    urls.add(n.value)
        assert any("intermediate" in u for u in urls)

    def test_leaf_aki_matches_intermediate_ski(self, intermediate_manager, leaf_key, chain):
        csr = _make_external_leaf_csr(leaf_key, "leaf.example.com")
        crt = intermediate_manager.sign_csr(
            signer=chain["intermediate"], csr=csr, days=90, is_ca=False
        )
        crypto_crt = _crypto_cert(crt)
        intermediate_crypto = _crypto_cert(chain["intermediate"])
        aki = crypto_crt.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
        ski = intermediate_crypto.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        assert aki.key_identifier == ski.key_identifier

    def test_no_duplicate_extensions(self, intermediate_manager, leaf_key, chain):
        csr = _make_external_leaf_csr(leaf_key, "leaf.example.com")
        crt = intermediate_manager.sign_csr(
            signer=chain["intermediate"], csr=csr, days=90, is_ca=False
        )
        oids = [str(e["extnID"]) for e in crt["tbsCertificate"]["extensions"]]
        assert len(oids) == len(set(oids))

    def test_leaf_san_carried_from_csr(self, intermediate_manager, leaf_key, chain):
        csr = _make_external_leaf_csr(leaf_key, "leaf.example.com", dns=["leaf.example.com", "www.leaf.example.com"])
        crt = intermediate_manager.sign_csr(
            signer=chain["intermediate"], csr=csr, days=90, is_ca=False
        )
        crypto_crt = _crypto_cert(crt)
        san = crypto_crt.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = {n.value for n in san if isinstance(n, x509.DNSName)}
        assert dns_names == {"leaf.example.com", "www.leaf.example.com"}


class TestSignCsrDer:

    def test_equivalent_to_sign_csr(self, root_manager):
        csr = root_manager.create_csr()
        csr_der = der_encoder(csr)

        cert_a = root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)
        cert_b = root_manager.sign_csr_der(signer=None, csr_der=csr_der, days=3650, is_ca=True)

        for field in ("subject", "issuer", "subjectPublicKeyInfo"):
            assert der_encoder(cert_a["tbsCertificate"][field]) == der_encoder(cert_b["tbsCertificate"][field])


class TestCreateCrl:

    @pytest.fixture
    def signed_root(self, root_manager):
        csr = root_manager.create_csr()
        return root_manager.sign_csr(signer=None, csr=csr, days=3650, is_ca=True)

    def _revoked_entry(self, serial: int, revocation_date: datetime, reason: str = "keyCompromise") -> IssuedCertificate:
        entry = MagicMock(spec=IssuedCertificate)
        entry.serial = der_encoder(univ.Integer(serial))
        entry.revocation_date = revocation_date
        entry.revocation_reason = reason
        return entry

    def test_empty_crl_builds(self, root_manager, signed_root):
        crl_asn1 = root_manager.create_crl(signer=signed_root, revoked_certs=[], crl_number=1)
        assert isinstance(crl_asn1, rfc5280.CertificateList)

    def test_crl_signature_verifies_against_root(self, root_manager, signed_root):
        crl_asn1 = root_manager.create_crl(signer=signed_root, revoked_certs=[], crl_number=1)
        crl_der = der_encoder(crl_asn1)
        crl = x509.load_der_x509_crl(crl_der)
        root_crypto = _crypto_cert(signed_root)
        assert crl.is_signature_valid(root_crypto.public_key())

    def test_crl_issuer_matches_signer_subject(self, root_manager, signed_root):
        crl = root_manager.create_crl(signer=signed_root, revoked_certs=[], crl_number=1)
        assert der_encoder(crl["tbsCertList"]["issuer"]) == der_encoder(signed_root["tbsCertificate"]["subject"])

    def test_revoked_entries_present(self, root_manager, signed_root):
        revoked = [
            self._revoked_entry(101, datetime(2025, 6, 1, tzinfo=timezone.utc)),
            self._revoked_entry(102, datetime(2025, 6, 2, tzinfo=timezone.utc)),
            self._revoked_entry(103, datetime(2025, 6, 3, tzinfo=timezone.utc)),
        ]
        crl_asn1 = root_manager.create_crl(signer=signed_root, revoked_certs=revoked, crl_number=1)
        crl_der = der_encoder(crl_asn1)
        crl = x509.load_der_x509_crl(crl_der)
        serials = {entry.serial_number for entry in crl}
        assert serials == {101, 102, 103}

    def test_revocation_reason_recorded(self, root_manager, signed_root):
        revoked = [
            self._revoked_entry(200, datetime(2025, 6, 1, tzinfo=timezone.utc), reason="keyCompromise"),
        ]
        crl_asn1 = root_manager.create_crl(signer=signed_root, revoked_certs=revoked, crl_number=1)
        crl_der = der_encoder(crl_asn1)
        crl = x509.load_der_x509_crl(crl_der)
        entry = next(iter(crl))
        ext = entry.extensions.get_extension_for_class(x509.CRLReason)
        assert ext.value.reason == x509.ReasonFlags.key_compromise

    def test_crl_signature_algorithm_in_outer_matches_tbs(self, root_manager, signed_root):
        crl = root_manager.create_crl(signer=signed_root, revoked_certs=[], crl_number=1)
        assert der_encoder(crl["signatureAlgorithm"]) == der_encoder(crl["tbsCertList"]["signature"])


class TestChainValidity:
    @pytest.fixture
    def signed_chain(self, root_manager, intermediate_manager, leaf_key):
        root_csr = root_manager.create_csr()
        root_cert = root_manager.sign_csr(signer=None, csr=root_csr, days=3650, is_ca=True)

        intermediate_csr = intermediate_manager.create_csr()
        intermediate_cert = root_manager.sign_csr(
            signer=root_cert, csr=intermediate_csr, days=1825, is_ca=True
        )

        leaf_csr = _make_external_leaf_csr(leaf_key, "leaf.example.com")
        leaf_cert = intermediate_manager.sign_csr(
            signer=intermediate_cert, csr=leaf_csr, days=90, is_ca=False
        )

        return {
            "root": _crypto_cert(root_cert),
            "intermediate": _crypto_cert(intermediate_cert),
            "leaf": _crypto_cert(leaf_cert),
        }

    def test_root_self_signed(self, signed_chain):
        signed_chain["root"].verify_directly_issued_by(signed_chain["root"])

    def test_intermediate_signed_by_root(self, signed_chain):
        signed_chain["intermediate"].verify_directly_issued_by(signed_chain["root"])

    def test_leaf_signed_by_intermediate(self, signed_chain):
        signed_chain["leaf"].verify_directly_issued_by(signed_chain["intermediate"])

    def test_wrong_parent_fails(self, signed_chain):
        with pytest.raises(Exception):
            signed_chain["leaf"].verify_directly_issued_by(signed_chain["root"])

    def test_all_three_serial_numbers_distinct(self, signed_chain):
        serials = {
            signed_chain["root"].serial_number,
            signed_chain["intermediate"].serial_number,
            signed_chain["leaf"].serial_number,
        }
        assert len(serials) == 3

    def test_chain_dates_well_ordered(self, signed_chain):
        now = datetime.now(timezone.utc)
        for cert in signed_chain.values():
            assert cert.not_valid_before_utc < now
            assert cert.not_valid_after_utc > now

    def test_three_distinct_subject_keys(self, signed_chain):
        pks = {
            signed_chain["root"].public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            signed_chain["intermediate"].public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            signed_chain["leaf"].public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        }
        assert len(pks) == 3
