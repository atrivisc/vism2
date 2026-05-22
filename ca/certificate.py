import cryptography
import cryptography.exceptions
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ
from pyasn1.type.base import Asn1Item
from pyasn1_modules import rfc2986, rfc5280, rfc2315, rfc4055
from pyasn1_modules.rfc5280 import CertificateList

from ca.config import CertificateConfig
from ca.crypto.build import build_certification_request_info, build_revoked_certificate_entry, build_tbs_cert_list, build_tbs_certificate
from ca.crypto.signer import Signer
from ca.crypto.util import get_ans1_time, get_algorithm_identifier
from ca.database import IssuedCertificate
from vism_lib.errors import VismBreakingException

_revocation_reason_map = {
    "unspecified": rfc5280.CRLReason("unspecified"),
    "keyCompromise": rfc5280.CRLReason("keyCompromise"),
    "cACompromise": rfc5280.CRLReason("cACompromise"),
    "affiliationChanged": rfc5280.CRLReason("affiliationChanged"),
    "superseded": rfc5280.CRLReason("superseded"),
    "cessationOfOperation": rfc5280.CRLReason("cessationOfOperation"),
    "certificateHold": rfc5280.CRLReason("certificateHold"),
    "removeFromCRL": rfc5280.CRLReason("removeFromCRL"),
    "privilegeWithdrawn": rfc5280.CRLReason("privilegeWithdrawn"),
    "aACompromise": rfc5280.CRLReason("aACompromise"),
}

_rsa_pss_map = {
    "SHA256": rfc4055.rSASSA_PSS_SHA256_Identifier,
    "SHA384": rfc4055.rSASSA_PSS_SHA384_Identifier,
    "SHA512": rfc4055.rSASSA_PSS_SHA512_Identifier,
}

class CertificateManager:
    """
    Represents a certificate and provides methods for operations such as
    generating, signing, and managing CRLs.
    """
    CSR_VERSION = 0x0
    CERT_VERSION = 0x2
    CRL_VERSION = 0x1
    CSR_SIGN_HASH_ALG = "SHA384"
    CRT_SIGN_HASH_ALG = "SHA384"
    CRL_SIGN_HASH_ALG = "SHA384"

    def __init__(self, signer: Signer, config: CertificateConfig, public_key_bytes: bytes):
        self.signer = signer
        self.config = config

        self.public_key_bytes = public_key_bytes

        try:
            self.public_key = serialization.load_der_public_key(public_key_bytes)
        except (ValueError, cryptography.exceptions.UnsupportedAlgorithm):
            self.public_key = serialization.load_pem_public_key(public_key_bytes)

        if self.config.externally_managed and (self.config.certificate_pem is None or self.config.crl_pem is None):
            raise VismBreakingException(
                f"Certificate {self.config.name} is externally managed"
                f", but no certificate or CRL was provided in the config."
            )

    def _sign_object(self, obj: Asn1Item, hash_alg: str) -> univ.BitString:
        signature_bytes = self.signer.sign(der_encoder(obj), hash_alg)
        return univ.BitString.fromHexString(signature_bytes.hex())

    def create_csr(self) -> rfc2986.CertificationRequest:
        all_csr_extensions = [
            self.config.x509.basic_constraints,
            self.config.x509.key_usage,
            self.config.x509.extended_key_usage,
            self.config.x509.subject_alternative_name,
            self.config.x509.authority_info_access,
            self.config.x509.crl_distribution_points
        ]
        requested_extensions = [ext.to_asn1_ext() for ext in all_csr_extensions if ext is not None]

        ### CSR info ###
        csr_info = build_certification_request_info(
            subject=self.config.x509.subject_name.to_asn1(),
            requested_extensions=requested_extensions,
            public_key_bytes=self.public_key_bytes
        )

        ### CSR ###
        csr = rfc2986.CertificationRequest()
        csr["certificationRequestInfo"] = csr_info

        ### CSR Signing ###
        signature_algorithm = get_algorithm_identifier(self.public_key, self.CSR_SIGN_HASH_ALG)
        signature = self._sign_object(csr_info, self.CSR_SIGN_HASH_ALG)
        csr["signatureAlgorithm"] = signature_algorithm
        csr["signature"] = signature

        return csr

    def sign_csr(self, signer: rfc5280.Certificate | None, csr: rfc2986.CertificationRequest, days: int, is_ca: bool) -> rfc5280.Certificate:
        # build_tbs_certificate reads requested extensions by treating
        # the CSR's AttributeValues as DER bytes (Any), which only works
        # if the CSR has been through DER decoding. Round-trip here so
        # callers don't need to think about CSR provenance.
        csr = der_decoder(der_encoder(csr), asn1Spec=rfc2986.CertificationRequest())[0]

        if signer is not None:
            signer_spki_der = der_encoder(signer['tbsCertificate']['subjectPublicKeyInfo'])
            signer_public_key = serialization.load_der_public_key(signer_spki_der)
        else:
            signer_public_key = self.public_key

        tbs_cert = build_tbs_certificate(
            issuer_cert=signer,
            csr=csr,
            days=days,
            signature_algorithm=get_algorithm_identifier(signer_public_key, self.CSR_SIGN_HASH_ALG),
            is_ca=is_ca,
            authority_info_access_ext=self.config.x509.authority_info_access.to_asn1_ext()
                if not is_ca and self.config.x509.authority_info_access else None,
            crl_distribution_points_ext=self.config.x509.crl_distribution_points.to_asn1_ext()
                if not is_ca and self.config.x509.crl_distribution_points else None,
        )

        ### Certificate ###
        signature_algorithm = get_algorithm_identifier(signer_public_key, self.CRT_SIGN_HASH_ALG)
        signature = self._sign_object(tbs_cert, self.CRT_SIGN_HASH_ALG)

        crt = rfc5280.Certificate()
        crt["tbsCertificate"] = tbs_cert
        crt["signatureAlgorithm"] = signature_algorithm
        crt["signature"] = signature

        return crt

    def sign_csr_der(self, signer: rfc5280.Certificate, csr_der: bytes, days: int, is_ca: bool) -> rfc5280.Certificate:
        csr = der_decoder(csr_der, asn1Spec=rfc2986.CertificationRequest())[0]
        return self.sign_csr(signer, csr, days, is_ca)


    def create_crl(self, signer: rfc5280.Certificate, revoked_certs: list[IssuedCertificate]) -> CertificateList:
        revoked_cert_entries = [
            build_revoked_certificate_entry(
                serial=der_decoder(issued_cert.serial, asn1Spec=rfc2315.SerialNumber())[0],
                revocation_time=get_ans1_time(issued_cert.revocation_date),
                revocation_reason=_revocation_reason_map[issued_cert.revocation_reason]
            )
            for issued_cert in revoked_certs
        ]

        signer_spki_der = der_encoder(signer['tbsCertificate']['subjectPublicKeyInfo'])
        signer_public_key = serialization.load_der_public_key(signer_spki_der)

        tbs_crl = build_tbs_cert_list(
            issuer_cert=signer,
            days=self.config.x509.crl_days,
            signature_algorithm=get_algorithm_identifier(signer_public_key, self.CRL_SIGN_HASH_ALG),
            revoked_certificate_entries=revoked_cert_entries
        )

        signature_algorithm = get_algorithm_identifier(signer_public_key, self.CRL_SIGN_HASH_ALG)
        signature = self._sign_object(tbs_crl, self.CRL_SIGN_HASH_ALG)

        crl = CertificateList()
        crl['tbsCertList'] = tbs_crl
        crl['signatureAlgorithm'] = signature_algorithm
        crl['signature'] = signature

        return crl
