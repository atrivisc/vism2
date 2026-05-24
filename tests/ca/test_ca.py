from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1_modules import rfc5280

from ca.config import (
    CAConfig,
    CertificateConfig,
    KeyConfig,
    SupportedKeyAlgorithms,
    ValidRevocationReasons,
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
from ca.crypto.util import csr_der_to_pem
from ca.database import CertificateEntity, IssuedCertificate
from ca.main import VismCA
from vism_lib.config import Security
from vism_lib.data.exchange import DataExchangeCSRMessage, DataExchangeCertMessage
from vism_lib.errors import VismBreakingException, VismException

from tests.ca._helpers import (
    FakeDataExchange,
    FakeS3Client,
    make_external_leaf_csr,
)


class FakeElection:
    is_leader = False
    election_interval = 30

    def __init__(self):
        self.shutdown_event = asyncio.Event()

    async def follower_heartbeat(self):
        pass

    async def leader_heartbeat(self):
        pass

    async def resign(self, resign_callback):
        await resign_callback()

    async def run(self, resign_callback, leader_callback, follower_callback):
        pass


def _ca_x509(
    cn: str,
    *,
    path_length: int = 0,
    aia_url: str | None = "http://ocsp.example.com",
    crl_url: str | None = "http://crl.example.com/x.crl",
    days: int = 3650,
    crl_days: int = 7,
) -> X509Config:
    kwargs: dict = dict(
        days=days, crl_days=crl_days,
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


def _cert_config(name: str, x509_cfg: X509Config | None = None, *, signed_by: str | None = None) -> CertificateConfig:
    kwargs: dict = {
        "name": name,
        "key": KeyConfig(algorithm=SupportedKeyAlgorithms.ec, curve="secp256r1"),
        "x509": x509_cfg or _ca_x509(name),
    }
    if signed_by is not None:
        kwargs["signed_by"] = signed_by
    return CertificateConfig(**kwargs)


def _ca_config(*certs: CertificateConfig) -> CAConfig:
    return CAConfig(
        security=Security(data_validation_key="test-key"),
        x509_certificates=list(certs),
    )


def _make_visma_ca(
    db,
    key_manager,
    *certs: CertificateConfig,
    s3: FakeS3Client | None = None,
    data_exchange: FakeDataExchange | None = None,
    election: FakeElection | None = None,
) -> tuple[VismCA, FakeS3Client, FakeDataExchange]:
    s3 = s3 or FakeS3Client()
    data_exchange = data_exchange or FakeDataExchange()
    election = election or FakeElection()
    ca = VismCA(
        config=_ca_config(*certs),
        key_manager=key_manager,
        database=db,
        s3_client=s3,
        election=election,
        data_exchange_module=data_exchange,
    )
    return ca, s3, data_exchange


class TestRevokeCertificate:
    def _setup(self, db, key_manager):
        ca, _, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        asyncio.run(ca.load_certificates())

        root_entity = db.get_cert_by_name("root")
        ic = IssuedCertificate(
            status_flag="g",
            expiration_date=datetime(2030, 1, 1),
            serial=der_encoder(rfc5280.CertificateSerialNumber(42)),
            subject=b"\x30\x05",
            ca=root_entity,
        )
        ic.ca_id = root_entity.id
        ic = db.save_to_db(ic)
        return ca, ic

    def test_sets_status_to_revoked(self, db, key_manager):
        ca, ic = self._setup(db, key_manager)
        ca.revoke_certificate(ic, ValidRevocationReasons.keyCompromise)
        assert ic.status_flag == "r"

    def test_records_reason(self, db, key_manager):
        ca, ic = self._setup(db, key_manager)
        ca.revoke_certificate(ic, ValidRevocationReasons.keyCompromise)
        assert ic.revocation_reason == ValidRevocationReasons.keyCompromise.value

    def test_records_revocation_date(self, db, key_manager):
        ca, ic = self._setup(db, key_manager)
        fixed = datetime(2025, 6, 15, 12, 0, tzinfo=timezone.utc)
        ca.revoke_certificate(ic, ValidRevocationReasons.superseded, now=fixed)
        assert ic.revocation_date == fixed

    def test_default_revocation_date_is_now(self, db, key_manager):
        ca, ic = self._setup(db, key_manager)
        before = datetime.now(timezone.utc)
        ca.revoke_certificate(ic, ValidRevocationReasons.unspecified)
        after = datetime.now(timezone.utc)
        assert before.replace(tzinfo=None) <= ic.revocation_date.replace(tzinfo=None) <= after.replace(tzinfo=None)

    def test_persists_to_db(self, db, key_manager):
        ca, ic = self._setup(db, key_manager)
        ca.revoke_certificate(ic, ValidRevocationReasons.keyCompromise)

        refetched = db.get_issued_certificate_by_serial(42)
        assert refetched is not None
        assert refetched.status_flag == "r"
        assert refetched.revocation_reason == "keyCompromise"

    def test_double_revocation_raises(self, db, key_manager):
        ca, ic = self._setup(db, key_manager)
        ca.revoke_certificate(ic, ValidRevocationReasons.keyCompromise)
        with pytest.raises(VismBreakingException, match="already revoked"):
            ca.revoke_certificate(ic, ValidRevocationReasons.superseded)


class TestBuildPemChain:
    def test_returns_pem_string(self, db, key_manager):
        ca, _, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        asyncio.run(ca.load_certificates())

        chain_pem = ca.build_pem_chain("root")
        assert isinstance(chain_pem, str)
        assert chain_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert "-----END CERTIFICATE-----" in chain_pem

    def test_propagates_missing_cert(self, db, key_manager):
        ca, _, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        with pytest.raises(VismException, match="not found"):
            ca.build_pem_chain("nonexistent")


class TestBuildCertificateManager:

    def test_returns_configured_certificate_manager(self, db, key_manager):
        ca, _, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        cert_config = ca.config.x509_certificates[0]

        manager = ca._build_certificate_manager(cert_config)
        assert manager.config is cert_config
        assert isinstance(manager.public_key, ec.EllipticCurvePublicKey)

    def test_key_manager_keypair_is_used(self, db, key_manager):
        ca, _, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        cert_config = ca.config.x509_certificates[0]

        mgr_a = ca._build_certificate_manager(cert_config)
        mgr_b = ca._build_certificate_manager(cert_config)
        from cryptography.hazmat.primitives import serialization
        pa = mgr_a.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pb = mgr_b.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert pa == pb


class TestIssueCert:

    def _setup(self, db, key_manager, cn: str = "root"):
        cfg = _cert_config(cn, _ca_x509(cn, path_length=2))
        ca, _, _ = _make_visma_ca(db, key_manager, cfg)
        mgr = ca._build_certificate_manager(cfg)
        db_entry = CertificateEntity(name=cn, externally_managed=False, signer=None)
        return ca, mgr, db_entry

    def test_populates_crt_der(self, db, key_manager):
        ca, mgr, db_entry = self._setup(db, key_manager)
        ca._issue_cert(
            cert=mgr, issuer_cert=mgr,
            issuer_db_entity=db_entry, db_entry=db_entry,
            issuer_asn1_cert=None,
        )
        assert db_entry.crt_der is not None
        assert db_entry.crt_der.startswith(b"\x30")

    def test_resulting_cert_loadable_by_cryptography(self, db, key_manager):
        ca, mgr, db_entry = self._setup(db, key_manager)
        ca._issue_cert(
            cert=mgr, issuer_cert=mgr,
            issuer_db_entity=db_entry, db_entry=db_entry,
            issuer_asn1_cert=None,
        )
        crt = x509.load_der_x509_certificate(db_entry.crt_der)
        assert "CN=root" in crt.subject.rfc4514_string()

    def test_appends_issued_certificate(self, db, key_manager):
        ca, mgr, db_entry = self._setup(db, key_manager)
        ca._issue_cert(
            cert=mgr, issuer_cert=mgr,
            issuer_db_entity=db_entry, db_entry=db_entry,
            issuer_asn1_cert=None,
        )
        assert len(db_entry.issued_certificates) == 1
        entry = db_entry.issued_certificates[0]
        assert entry.status_flag == "v"
        assert entry.serial != b""
        assert entry.subject != b""

    def test_expiration_date_matches_cert_validity(self, db, key_manager):
        ca, mgr, db_entry = self._setup(db, key_manager)
        ca._issue_cert(
            cert=mgr, issuer_cert=mgr,
            issuer_db_entity=db_entry, db_entry=db_entry,
            issuer_asn1_cert=None,
        )
        crt = x509.load_der_x509_certificate(db_entry.crt_der)
        assert db_entry.issued_certificates[0].expiration_date.replace(tzinfo=None) == \
            crt.not_valid_after_utc.replace(tzinfo=None)

    def test_honors_now_parameter(self, db, key_manager):
        ca, mgr, db_entry = self._setup(db, key_manager)
        fixed = datetime(2025, 6, 15, 12, 0, tzinfo=timezone.utc)
        ca._issue_cert(
            cert=mgr, issuer_cert=mgr,
            issuer_db_entity=db_entry, db_entry=db_entry,
            issuer_asn1_cert=None, now=fixed,
        )
        crt = x509.load_der_x509_certificate(db_entry.crt_der)
        from datetime import timedelta
        assert crt.not_valid_before_utc == fixed - timedelta(hours=1)


class TestIssueCrl:
    def _root_with_cert(self, db, key_manager):
        cfg = _cert_config("root", _ca_x509("root", path_length=2))
        ca, _, _ = _make_visma_ca(db, key_manager, cfg)
        mgr = ca._build_certificate_manager(cfg)
        db_entry = CertificateEntity(name="root", externally_managed=False, signer=None)
        ca._issue_cert(
            cert=mgr, issuer_cert=mgr,
            issuer_db_entity=db_entry, db_entry=db_entry,
            issuer_asn1_cert=None,
        )
        db_entry = db.save_to_db(db_entry)
        return ca, mgr, db_entry

    def test_populates_crl_der(self, db, key_manager):
        ca, mgr, db_entry = self._root_with_cert(db, key_manager)
        ca._issue_crl(cert=mgr, db_entry=db_entry)
        assert db_entry.crl_der is not None
        assert db_entry.crl_der.startswith(b"\x30")

    def test_crl_loadable_by_cryptography(self, db, key_manager):
        ca, mgr, db_entry = self._root_with_cert(db, key_manager)
        ca._issue_crl(cert=mgr, db_entry=db_entry)
        crl = x509.load_der_x509_crl(db_entry.crl_der)
        assert "CN=root" in crl.issuer.rfc4514_string()

    def test_empty_crl_when_no_revocations(self, db, key_manager):
        ca, mgr, db_entry = self._root_with_cert(db, key_manager)
        ca._issue_crl(cert=mgr, db_entry=db_entry)
        crl = x509.load_der_x509_crl(db_entry.crl_der)
        assert len(list(crl)) == 0

    def test_crl_signed_by_own_key(self, db, key_manager):
        ca, mgr, db_entry = self._root_with_cert(db, key_manager)
        ca._issue_crl(cert=mgr, db_entry=db_entry)

        own_cert = x509.load_der_x509_certificate(db_entry.crt_der)
        crl = x509.load_der_x509_crl(db_entry.crl_der)
        assert crl.is_signature_valid(own_cert.public_key())


class TestSaveCertificate:
    def test_uploads_crt_when_present(self, db, key_manager):
        ca, s3, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        entity = CertificateEntity(name="root", externally_managed=False, signer=None)
        entity.crt_der = b"\xfake-cert"[:9]
        asyncio.run(ca.save_certificate("root", entity))
        assert "crt/root.crt" in s3.uploaded_keys()
        assert s3.get_upload("crt/root.crt").data == b"\xfake-cert"[:9]

    def test_uploads_crl_when_present(self, db, key_manager):
        ca, s3, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        entity = CertificateEntity(name="root", externally_managed=False, signer=None)
        entity.crl_der = b"\xfake-crl"[:8]
        asyncio.run(ca.save_certificate("root", entity))
        assert "crl/root.crl" in s3.uploaded_keys()

    def test_no_upload_when_ders_absent(self, db, key_manager):
        ca, s3, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        entity = CertificateEntity(name="root", externally_managed=False, signer=None)
        asyncio.run(ca.save_certificate("root", entity))
        assert s3.uploaded_keys() == []

    def test_persists_to_db(self, db, key_manager):
        ca, _, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        entity = CertificateEntity(name="root", externally_managed=False, signer=None)
        asyncio.run(ca.save_certificate("root", entity))
        assert db.get_cert_by_name("root") is not None


class TestLifecycleCallbacks:

    def test_async_shutdown_cleans_up_data_exchange(self, db, key_manager):
        ca, _, dx = _make_visma_ca(db, key_manager, _cert_config("root"))
        asyncio.run(ca.async_shutdown())
        assert dx.cleanup_calls == [True]

    def test_follower_run_cleans_up_data_exchange(self, db, key_manager):
        ca, _, dx = _make_visma_ca(db, key_manager, _cert_config("root"))
        asyncio.run(ca.follower_run())
        assert dx.cleanup_calls == [True]

    def test_leader_run_subscribes_to_csr_messages(self, db, key_manager):
        ca, s3, dx = _make_visma_ca(db, key_manager, _cert_config("root"))
        asyncio.run(ca.leader_run())
        assert s3.bucket_created is True
        assert len(dx.subscriptions) == 1
        assert dx.subscriptions[0].message_class is DataExchangeCSRMessage
        assert "root" in ca.certificates


# =========================================================================
# TestLoadCertificate
# =========================================================================

class TestLoadCertificate:

    def _build(self, db, key_manager, cfg: CertificateConfig):
        ca, _, _ = _make_visma_ca(db, key_manager, cfg)
        mgr = ca._build_certificate_manager(cfg)
        db_entry = CertificateEntity(
            name=cfg.name, externally_managed=cfg.externally_managed, signer=None,
        )
        return ca, mgr, db_entry

    @staticmethod
    def _build_external_ca_pems(cn: str = "ext-root") -> tuple[str, str, ec.EllipticCurvePrivateKey]:
        from cryptography.hazmat.primitives import serialization as _serial
        ec_key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
            .public_key(ec_key.public_key())
            .serial_number(1)
            .not_valid_before(datetime(2024, 1, 1))
            .not_valid_after(datetime(2034, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ec_key, hashes.SHA384())
        )
        cert_pem = cert.public_bytes(_serial.Encoding.PEM).decode()
        crl = (x509.CertificateRevocationListBuilder()
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
            .last_update(datetime(2024, 1, 1))
            .next_update(datetime(2024, 12, 31))
            .sign(ec_key, hashes.SHA384())
        )
        crl_pem = crl.public_bytes(_serial.Encoding.PEM).decode()
        return cert_pem, crl_pem, ec_key

    @staticmethod
    def _sign_subordinate_with_external_ca(
        sub_pubkey: ec.EllipticCurvePublicKey,
        sub_cn: str,
        ext_signing_key: ec.EllipticCurvePrivateKey,
        ext_cn: str = "ext-root",
    ) -> str:
        from cryptography.hazmat.primitives import serialization as _serial
        cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, sub_cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, ext_cn)]))
            .public_key(sub_pubkey)
            .serial_number(2)
            .not_valid_before(datetime(2024, 1, 1))
            .not_valid_after(datetime(2027, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(ext_signing_key, hashes.SHA384())
        )
        return cert.public_bytes(_serial.Encoding.PEM).decode()

    def test_self_signed_root_gets_cert_and_crl(self, db, key_manager):
        cfg = _cert_config("root")
        ca, mgr, db_entry = self._build(db, key_manager, cfg)

        issuer_db, returned = asyncio.run(ca.load_certificate(
            cert=mgr, db_entry=db_entry,
            issuer_cert=None, issuer_db_entity=None,
        ))
        assert returned is db_entry
        assert issuer_db is db_entry  # self-signed: issuer == subject
        assert db_entry.crt_der is not None
        assert db_entry.crl_der is not None

    def test_already_issued_cert_is_not_reissued(self, db, key_manager):
        cfg = _cert_config("root")
        ca, mgr, db_entry = self._build(db, key_manager, cfg)
        db_entry.crt_der = b"\x30\xaa\xbb\xcc"  # pre-existing fake

        with pytest.raises(Exception):
            asyncio.run(ca.load_certificate(
                cert=mgr, db_entry=db_entry,
                issuer_cert=None, issuer_db_entity=None,
            ))
        assert db_entry.crt_der == b"\x30\xaa\xbb\xcc"

    def test_externally_managed_loads_from_config(self, db, key_manager):
        ext_cert_pem, ext_crl_pem, _ = self._build_external_ca_pems()

        cfg = _cert_config("ext-root")
        cfg.externally_managed = True
        cfg.certificate_pem = ext_cert_pem
        cfg.crl_pem = ext_crl_pem

        ca, mgr, db_entry = self._build(db, key_manager, cfg)
        asyncio.run(ca.load_certificate(
            cert=mgr, db_entry=db_entry,
            issuer_cert=None, issuer_db_entity=None,
        ))
        loaded_cert = x509.load_der_x509_certificate(db_entry.crt_der)
        assert "CN=ext-root" in loaded_cert.subject.rfc4514_string()
        loaded_crl = x509.load_der_x509_crl(db_entry.crl_der)
        assert "CN=ext-root" in loaded_crl.issuer.rfc4514_string()

    def test_subordinate_under_external_ca_loads_pre_signed_cert(self, db, key_manager):
        ext_cert_pem, ext_crl_pem, ext_key = self._build_external_ca_pems()
        ext_cfg = _cert_config("ext-root")
        ext_cfg.externally_managed = True
        ext_cfg.certificate_pem = ext_cert_pem
        ext_cfg.crl_pem = ext_crl_pem

        sub_cfg = _cert_config("subordinate", _ca_x509("subordinate"), signed_by="ext-root")
        ca, _, _ = _make_visma_ca(db, key_manager, ext_cfg, sub_cfg)
        ext_mgr = ca._build_certificate_manager(ext_cfg)
        sub_mgr = ca._build_certificate_manager(sub_cfg)

        sub_cfg.certificate_pem = self._sign_subordinate_with_external_ca(
            sub_pubkey=sub_mgr.public_key,
            sub_cn="subordinate",
            ext_signing_key=ext_key,
        )

        ext_db = CertificateEntity(name="ext-root", externally_managed=True, signer=None)
        sub_db = CertificateEntity(name="subordinate", externally_managed=False, signer=ext_db)

        asyncio.run(ca.load_certificate(
            cert=ext_mgr, db_entry=ext_db,
            issuer_cert=None, issuer_db_entity=None,
        ))
        asyncio.run(ca.load_certificate(
            cert=sub_mgr, db_entry=sub_db,
            issuer_cert=ext_mgr, issuer_db_entity=ext_db,
        ))

        loaded_cert = x509.load_der_x509_certificate(sub_db.crt_der)
        assert "CN=subordinate" in loaded_cert.subject.rfc4514_string()
        assert "CN=ext-root" in loaded_cert.issuer.rfc4514_string()
        ext_cert = x509.load_pem_x509_certificate(ext_cert_pem.encode())
        loaded_cert.verify_directly_issued_by(ext_cert)
        assert sub_db.crl_der is not None

    def test_subordinate_under_external_ca_raises_for_manual_signing(self, db, key_manager):
        """Sub-case (b): a subordinate is configured under an externally-
        managed CA, but neither certificate_pem nor db crt_der is set.
        The CA can't issue the cert itself (it doesn't have the external
        CA's private key) so it raises VismException, embedding a CSR
        the operator can take to the external CA for signing."""
        # External root setup.
        ext_cert_pem, ext_crl_pem, _ = self._build_external_ca_pems()
        ext_cfg = _cert_config("ext-root")
        ext_cfg.externally_managed = True
        ext_cfg.certificate_pem = ext_cert_pem
        ext_cfg.crl_pem = ext_crl_pem

        # Subordinate WITHOUT certificate_pem — operator hasn't signed yet.
        sub_cfg = _cert_config("subordinate", _ca_x509("subordinate"), signed_by="ext-root")
        ca, _, _ = _make_visma_ca(db, key_manager, ext_cfg, sub_cfg)
        ext_mgr = ca._build_certificate_manager(ext_cfg)
        sub_mgr = ca._build_certificate_manager(sub_cfg)

        ext_db = CertificateEntity(name="ext-root", externally_managed=True, signer=None)
        sub_db = CertificateEntity(name="subordinate", externally_managed=False, signer=ext_db)

        asyncio.run(ca.load_certificate(
            cert=ext_mgr, db_entry=ext_db,
            issuer_cert=None, issuer_db_entity=None,
        ))
        with pytest.raises(VismException, match="needs to be manually signed"):
            asyncio.run(ca.load_certificate(
                cert=sub_mgr, db_entry=sub_db,
                issuer_cert=ext_mgr, issuer_db_entity=ext_db,
            ))

    def test_subordinate_under_external_ca_skips_load_when_already_in_db(self, db, key_manager):
        ext_cert_pem, ext_crl_pem, ext_key = self._build_external_ca_pems()
        ext_cfg = _cert_config("ext-root")
        ext_cfg.externally_managed = True
        ext_cfg.certificate_pem = ext_cert_pem
        ext_cfg.crl_pem = ext_crl_pem

        sub_cfg = _cert_config("subordinate", _ca_x509("subordinate"), signed_by="ext-root")
        ca, _, _ = _make_visma_ca(db, key_manager, ext_cfg, sub_cfg)
        ext_mgr = ca._build_certificate_manager(ext_cfg)
        sub_mgr = ca._build_certificate_manager(sub_cfg)

        existing_pem = self._sign_subordinate_with_external_ca(
            sub_pubkey=sub_mgr.public_key,
            sub_cn="subordinate",
            ext_signing_key=ext_key,
        )
        existing_der = x509.load_pem_x509_certificate(existing_pem.encode()).public_bytes(
            serialization.Encoding.DER
        )

        ext_db = CertificateEntity(name="ext-root", externally_managed=True, signer=None)
        sub_db = CertificateEntity(name="subordinate", externally_managed=False, signer=ext_db)
        sub_db.crt_der = existing_der

        asyncio.run(ca.load_certificate(
            cert=ext_mgr, db_entry=ext_db,
            issuer_cert=None, issuer_db_entity=None,
        ))
        asyncio.run(ca.load_certificate(
            cert=sub_mgr, db_entry=sub_db,
            issuer_cert=ext_mgr, issuer_db_entity=ext_db,
        ))

        assert sub_db.crt_der == existing_der
        assert sub_db.crl_der is not None


class TestLoadCertificates:
    def test_single_root_cert(self, db, key_manager):
        ca, s3, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        result = asyncio.run(ca.load_certificates())

        assert set(result.keys()) == {"root"}
        assert db.get_cert_by_name("root") is not None
        assert "crt/root.crt" in s3.uploaded_keys()
        assert "crl/root.crl" in s3.uploaded_keys()

    def test_chain_root_then_intermediate(self, db, key_manager):
        ca, _, _ = _make_visma_ca(
            db, key_manager,
            _cert_config("root", _ca_x509("root", path_length=1)),
            _cert_config("intermediate", _ca_x509("intermediate"), signed_by="root"),
        )
        result = asyncio.run(ca.load_certificates())

        assert set(result.keys()) == {"root", "intermediate"}
        assert db.get_cert_by_name("root") is not None
        assert db.get_cert_by_name("intermediate") is not None

    def test_intermediate_cert_verifies_against_root(self, db, key_manager):
        ca, _, _ = _make_visma_ca(
            db, key_manager,
            _cert_config("root", _ca_x509("root", path_length=1)),
            _cert_config("intermediate", _ca_x509("intermediate"), signed_by="root"),
        )
        asyncio.run(ca.load_certificates())

        root_der = db.get_cert_by_name("root").crt_der
        intermediate_der = db.get_cert_by_name("intermediate").crt_der
        root_cert = x509.load_der_x509_certificate(root_der)
        intermediate_cert = x509.load_der_x509_certificate(intermediate_der)
        intermediate_cert.verify_directly_issued_by(root_cert)

    def test_intermediate_crl_signed_by_intermediate(self, db, key_manager):
        ca, _, _ = _make_visma_ca(
            db, key_manager,
            _cert_config("root", _ca_x509("root", path_length=1)),
            _cert_config("intermediate", _ca_x509("intermediate"), signed_by="root"),
        )
        asyncio.run(ca.load_certificates())

        intermediate_entity = db.get_cert_by_name("intermediate")
        intermediate_cert = x509.load_der_x509_certificate(intermediate_entity.crt_der)
        intermediate_crl = x509.load_der_x509_crl(intermediate_entity.crl_der)

        assert "CN=intermediate" in intermediate_crl.issuer.rfc4514_string()
        assert intermediate_crl.is_signature_valid(intermediate_cert.public_key())

    def test_out_of_order_config_raises(self, db, key_manager):
        ca, _, _ = _make_visma_ca(
            db, key_manager,
            _cert_config("intermediate", _ca_x509("intermediate"), signed_by="root"),
            _cert_config("root", _ca_x509("root", path_length=1)),
        )
        with pytest.raises(VismException, match="signed by"):
            asyncio.run(ca.load_certificates())

    def test_idempotent_on_reload(self, db, key_manager):
        ca, _, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        first = asyncio.run(ca.load_certificates())
        first_der = first["root"]
        cert_der_after_first = db.get_cert_by_name("root").crt_der

        ca2, _, _ = _make_visma_ca(db, key_manager, _cert_config("root"))
        asyncio.run(ca2.load_certificates())

        assert db.get_cert_by_name("root").crt_der == cert_der_after_first


class TestHandleCsrFromAcme:
    def _setup_intermediate_ca(self, db, key_manager):
        ca, _, dx = _make_visma_ca(
            db, key_manager,
            _cert_config("root", _ca_x509("root", path_length=1)),
            _cert_config("intermediate", _ca_x509("intermediate"), signed_by="root"),
        )
        ca.certificates = asyncio.run(ca.load_certificates())
        return ca, dx

    def _make_csr_message(self, ca_name: str = "intermediate") -> tuple[DataExchangeCSRMessage, ec.EllipticCurvePrivateKey]:
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf_csr_pem = make_external_leaf_csr(leaf_key, "leaf.example.com")
        leaf_csr_pem_str = csr_der_to_pem(der_encoder(leaf_csr_pem))
        msg = DataExchangeCSRMessage(
            order_id="order-1",
            ca_name=ca_name,
            csr_pem=leaf_csr_pem_str,
            days=90,
            module_args={},
        )
        return msg, leaf_key

    def test_signs_csr_and_sends_back_chain(self, db, key_manager):
        ca, dx = self._setup_intermediate_ca(db, key_manager)
        msg, _ = self._make_csr_message()
        asyncio.run(ca.handle_csr_from_acme(msg))

        assert len(dx.sent) == 1
        response = dx.sent[0]
        assert isinstance(response, DataExchangeCertMessage)
        assert response.order_id == "order-1"
        assert response.ca_name == "intermediate"

    def test_chain_includes_intermediate(self, db, key_manager):
        ca, dx = self._setup_intermediate_ca(db, key_manager)
        msg, _ = self._make_csr_message()
        asyncio.run(ca.handle_csr_from_acme(msg))

        chain = dx.sent[0].chain
        assert chain.count("-----BEGIN CERTIFICATE-----") == 2

    def test_unknown_ca_logs_and_returns_nothing(self, db, key_manager):
        ca, dx = self._setup_intermediate_ca(db, key_manager)
        msg, _ = self._make_csr_message(ca_name="nonexistent")
        asyncio.run(ca.handle_csr_from_acme(msg))

        assert dx.sent == []

    def test_invalid_csr_logs_and_returns_nothing(self, db, key_manager):
        ca, dx = self._setup_intermediate_ca(db, key_manager)
        msg = DataExchangeCSRMessage(
            order_id="order-bad",
            ca_name="intermediate",
            csr_pem="not a real csr",
            days=90,
            module_args={},
        )
        asyncio.run(ca.handle_csr_from_acme(msg))

        assert dx.sent == []

    def test_leaf_verifies_against_intermediate(self, db, key_manager):
        ca, dx = self._setup_intermediate_ca(db, key_manager)
        msg, _ = self._make_csr_message()
        asyncio.run(ca.handle_csr_from_acme(msg))

        chain = dx.sent[0].chain
        certs = []
        for block in chain.split("-----END CERTIFICATE-----"):
            block = block.strip()
            if not block:
                continue
            pem = block + "\n-----END CERTIFICATE-----"
            certs.append(x509.load_pem_x509_certificate(pem.encode()))

        leaf, intermediate = certs
        leaf.verify_directly_issued_by(intermediate)