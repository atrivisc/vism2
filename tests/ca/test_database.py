from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1_modules import rfc5280

from ca.database import CertificateEntity, IssuedCertificate
from vism_lib.errors import VismBreakingException, VismException


def _root_cert(**overrides) -> CertificateEntity:
    return CertificateEntity(
        name=overrides.pop("name", "root"),
        externally_managed=overrides.pop("externally_managed", False),
        signer=overrides.pop("signer", None),
        **overrides,
    )


def _issued_cert(ca: CertificateEntity, **overrides) -> IssuedCertificate:
    ic = IssuedCertificate(
        status_flag=overrides.pop("status_flag", "g"),
        expiration_date=overrides.pop("expiration_date", datetime(2030, 1, 1, tzinfo=timezone.utc)),
        serial=overrides.pop("serial", b"\x02\x01\x01"),
        subject=overrides.pop("subject", b"\x30\x05"),
        ca=ca,
        **overrides,
    )
    if ca.id is not None:
        ic.ca_id = ca.id
    return ic


def _encoded_serial(serial: int) -> bytes:
    return der_encoder(rfc5280.CertificateSerialNumber(serial))


class TestSaveAndSign:
    def test_save_populates_signature(self, db):
        saved = db.save_to_db(_root_cert(name="root"))
        assert saved.signature is not None
        assert len(saved.signature) == 32  # HMAC-SHA256

    def test_save_populates_id(self, db):
        saved = db.save_to_db(_root_cert(name="root"))
        assert saved.id is not None

    def test_signature_validates_after_save(self, db):
        saved = db.save_to_db(_root_cert(name="root"))
        assert db._validate_obj(saved) is True

    def test_signature_validates_for_issued_certificate(self, db):
        root = db.save_to_db(_root_cert(name="root"))
        ic = db.save_to_db(_issued_cert(root))
        assert db._validate_obj(ic) is True


class TestCertificateEntityToDict:

    def test_required_fields_present(self, db):
        ce = _root_cert(name="my-ca", externally_managed=True)
        d = ce.to_dict()
        assert d["name"] == "my-ca"
        assert d["externally_managed"] is True
        assert d["crl_number"] == 1  # default

    def test_null_ders_serialized_as_none(self, db):
        ce = _root_cert(name="root")
        d = ce.to_dict()
        assert d["crt_der"] is None
        assert d["crl_der"] is None

    def test_der_bytes_serialized_as_hex(self, db):
        ce = _root_cert(name="root")
        ce.crt_der = b"\x30\x82\x01\x02"
        ce.crl_der = b"\xff\xee"
        d = ce.to_dict()
        assert d["crt_der"] == "3082010 2".replace(" ", "")  # 30820102
        assert d["crl_der"] == "ffee"


class TestIssuedCertificateToDict:

    def test_required_fields_present(self, db):
        root = db.save_to_db(_root_cert(name="root"))
        ic = _issued_cert(root, status_flag="g")
        d = ic.to_dict()
        assert d["status_flag"] == "g"
        assert d["serial"] == "020101"
        assert d["subject"] == "3005"

    def test_revocation_fields_default_to_none(self, db):
        root = db.save_to_db(_root_cert(name="root"))
        ic = _issued_cert(root)
        d = ic.to_dict()
        assert d["revocation_date"] is None
        assert d["revocation_reason"] is None

    def test_revocation_fields_serialized_when_set(self, db):
        root = db.save_to_db(_root_cert(name="root"))
        ic = _issued_cert(
            root,
            status_flag="r",
            revocation_date=datetime(2025, 6, 15, 12, 0, tzinfo=timezone.utc),
            revocation_reason="keyCompromise",
        )
        d = ic.to_dict()
        assert d["status_flag"] == "r"
        assert d["revocation_reason"] == "keyCompromise"
        assert d["revocation_date"] == "2025-06-15 12:00:00+00:00"


class TestGetCertByName:

    def test_returns_matching_cert(self, db):
        db.save_to_db(_root_cert(name="root"))
        result = db.get_cert_by_name("root")
        assert result is not None
        assert result.name == "root"

    def test_returns_none_when_not_found(self, db):
        assert db.get_cert_by_name("nonexistent") is None

    def test_picks_correct_cert_among_many(self, db):
        db.save_to_db(_root_cert(name="root"))
        db.save_to_db(_root_cert(name="intermediate"))
        db.save_to_db(_root_cert(name="leaf"))
        result = db.get_cert_by_name("intermediate")
        assert result.name == "intermediate"


class TestGetChainDers:

    def test_single_self_signed_root(self, db):
        root = _root_cert(name="root")
        root.crt_der = b"\x30\x01\x02\x03"
        db.save_to_db(root)
        chain = db.get_chain_ders("root")
        assert chain == [b"\x30\x01\x02\x03"]

    def test_two_level_chain_returns_leaf_then_root(self, db):
        root = _root_cert(name="root")
        root.crt_der = b"\xaa" * 4
        saved_root = db.save_to_db(root)

        intermediate = CertificateEntity(
            name="intermediate", externally_managed=False, signer=saved_root,
        )
        intermediate.crt_der = b"\xbb" * 4
        db.save_to_db(intermediate)

        chain = db.get_chain_ders("intermediate")
        assert chain == [b"\xbb" * 4, b"\xaa" * 4]

    def test_three_level_chain(self, db):
        root = _root_cert(name="root")
        root.crt_der = b"\xaa" * 4
        saved_root = db.save_to_db(root)

        intermediate = CertificateEntity(
            name="intermediate", externally_managed=False, signer=saved_root,
        )
        intermediate.crt_der = b"\xbb" * 4
        saved_intermediate = db.save_to_db(intermediate)

        leaf = CertificateEntity(
            name="leaf", externally_managed=False, signer=saved_intermediate,
        )
        leaf.crt_der = b"\xcc" * 4
        db.save_to_db(leaf)

        chain = db.get_chain_ders("leaf")
        assert chain == [b"\xcc" * 4, b"\xbb" * 4, b"\xaa" * 4]

    def test_raises_when_cert_not_found(self, db):
        with pytest.raises(VismException, match="not found in the database"):
            db.get_chain_ders("nonexistent")

    def test_raises_when_any_cert_in_chain_lacks_der(self, db):
        root = _root_cert(name="root")  # no crt_der set
        db.save_to_db(root)
        with pytest.raises(VismException, match="root.*no crt_der"):
            db.get_chain_ders("root")

    def test_raises_when_intermediate_lacks_der(self, db):
        root = _root_cert(name="root")
        root.crt_der = b"\xaa" * 4
        saved_root = db.save_to_db(root)

        intermediate = CertificateEntity(
            name="intermediate", externally_managed=False, signer=saved_root,
        )  # no crt_der
        saved_intermediate = db.save_to_db(intermediate)

        leaf = CertificateEntity(
            name="leaf", externally_managed=False, signer=saved_intermediate,
        )
        leaf.crt_der = b"\xcc" * 4
        db.save_to_db(leaf)

        with pytest.raises(VismException, match="intermediate.*no crt_der"):
            db.get_chain_ders("leaf")


class TestGetIssuedCertificateBySerial:

    def _setup(self, db, serial_int: int = 12345) -> tuple[CertificateEntity, IssuedCertificate]:
        root = db.save_to_db(_root_cert(name="root"))
        ic = db.save_to_db(_issued_cert(root, serial=_encoded_serial(serial_int)))
        return root, ic

    def test_lookup_by_int(self, db):
        _, ic = self._setup(db, serial_int=12345)
        result = db.get_issued_certificate_by_serial(12345)
        assert result is not None
        assert result.id == ic.id

    def test_lookup_by_hex_string(self, db):
        _, ic = self._setup(db, serial_int=12345)  # 12345 == 0x3039
        result = db.get_issued_certificate_by_serial("3039")
        assert result is not None
        assert result.id == ic.id

    def test_lookup_by_hex_string_with_prefix(self, db):
        _, ic = self._setup(db, serial_int=12345)
        result = db.get_issued_certificate_by_serial("0x3039")
        assert result is not None
        assert result.id == ic.id

    def test_returns_none_when_serial_not_in_db(self, db):
        self._setup(db, serial_int=12345)
        assert db.get_issued_certificate_by_serial(99999) is None

    def test_raises_on_invalid_hex(self, db):
        self._setup(db)
        with pytest.raises(VismBreakingException, match="Invalid serial number"):
            db.get_issued_certificate_by_serial("not-a-hex-string")


class TestGetRevokedCertificatesForIssuer:

    def test_returns_only_revoked(self, db):
        root = db.save_to_db(_root_cert(name="root"))
        db.save_to_db(_issued_cert(root, status_flag="g", serial=_encoded_serial(1)))
        db.save_to_db(_issued_cert(
            root, status_flag="r", serial=_encoded_serial(2),
            revocation_date=datetime(2025, 1, 1, tzinfo=timezone.utc), revocation_reason="keyCompromise",
        ))
        db.save_to_db(_issued_cert(
            root, status_flag="r", serial=_encoded_serial(3),
            revocation_date=datetime(2025, 2, 1, tzinfo=timezone.utc), revocation_reason="superseded",
        ))

        revoked = db.get_revoked_certificates_for_issuer(root.id)
        assert len(revoked) == 2
        serials = {bytes(r.serial) for r in revoked}
        assert serials == {_encoded_serial(2), _encoded_serial(3)}

    def test_returns_empty_when_no_revocations(self, db):
        root = db.save_to_db(_root_cert(name="root"))
        db.save_to_db(_issued_cert(root, status_flag="g", serial=_encoded_serial(1)))
        assert db.get_revoked_certificates_for_issuer(root.id) == []

    def test_returns_empty_for_unknown_issuer(self, db):
        assert db.get_revoked_certificates_for_issuer(uuid4()) == []

    def test_filters_by_issuer(self, db):
        root_a = db.save_to_db(_root_cert(name="root-a"))
        root_b = db.save_to_db(_root_cert(name="root-b"))
        db.save_to_db(_issued_cert(
            root_a, status_flag="r", serial=_encoded_serial(1),
            revocation_date=datetime(2025, 1, 1, tzinfo=timezone.utc), revocation_reason="keyCompromise",
        ))
        db.save_to_db(_issued_cert(
            root_b, status_flag="r", serial=_encoded_serial(2),
            revocation_date=datetime(2025, 1, 1, tzinfo=timezone.utc), revocation_reason="keyCompromise",
        ))

        revoked_a = db.get_revoked_certificates_for_issuer(root_a.id)
        revoked_b = db.get_revoked_certificates_for_issuer(root_b.id)
        assert len(revoked_a) == 1
        assert len(revoked_b) == 1
        assert bytes(revoked_a[0].serial) == _encoded_serial(1)
        assert bytes(revoked_b[0].serial) == _encoded_serial(2)


class TestGetIssuedCertificates:

    def test_returns_all_for_issuer_regardless_of_status(self, db):
        root = db.save_to_db(_root_cert(name="root"))
        db.save_to_db(_issued_cert(root, status_flag="g", serial=_encoded_serial(1)))
        db.save_to_db(_issued_cert(
            root, status_flag="r", serial=_encoded_serial(2),
            revocation_date=datetime(2025, 1, 1, tzinfo=timezone.utc), revocation_reason="superseded",
        ))
        result = db.get_issued_certificates(root.id)
        assert len(result) == 2

    def test_filters_by_issuer(self, db):
        root_a = db.save_to_db(_root_cert(name="root-a"))
        root_b = db.save_to_db(_root_cert(name="root-b"))
        db.save_to_db(_issued_cert(root_a, serial=_encoded_serial(1)))
        db.save_to_db(_issued_cert(root_b, serial=_encoded_serial(2)))
        db.save_to_db(_issued_cert(root_b, serial=_encoded_serial(3)))

        assert len(db.get_issued_certificates(root_a.id)) == 1
        assert len(db.get_issued_certificates(root_b.id)) == 2

class TestCascade:

    def test_deleting_ca_removes_issued_certs(self, db):
        root = db.save_to_db(_root_cert(name="root"))
        db.save_to_db(_issued_cert(root, serial=_encoded_serial(1)))
        db.save_to_db(_issued_cert(root, serial=_encoded_serial(2)))

        assert len(db.get_issued_certificates(root.id)) == 2

        with db._get_session() as session:
            to_delete = session.get(CertificateEntity, root.id)
            _ = to_delete.issued_certificates  # trigger lazy load
            session.delete(to_delete)
            session.commit()

        assert db.get_cert_by_name("root") is None
        assert db.get_issued_certificates(root.id) == []


class TestClearAllTables:

    def test_clears_certificates(self, db):
        db.save_to_db(_root_cert(name="root-a"))
        db.save_to_db(_root_cert(name="root-b"))
        assert db.get_cert_by_name("root-a") is not None

        db.clear_all_tables()

        assert db.get_cert_by_name("root-a") is None
        assert db.get_cert_by_name("root-b") is None

    def test_clears_issued_certificates(self, db):
        root = db.save_to_db(_root_cert(name="root"))
        db.save_to_db(_issued_cert(root, serial=_encoded_serial(1)))

        db.clear_all_tables()

        assert db.get_issued_certificates(root.id) == []

    def test_safe_to_call_on_empty_db(self, db):
        db.clear_all_tables()
        db.clear_all_tables()
