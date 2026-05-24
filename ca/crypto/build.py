import hashlib
import time
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from pyasn1.type import univ, tag
from pyasn1_modules import rfc2985, rfc5280, rfc2986

from ca.asn1 import ExtensionsRequest, RevokedCertificates, RevokedCertificateEntry
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from ca.crypto.util import get_ans1_time, get_extension_by_oid_from_certificate, generate_random_serial
from ca.errors import CryptoException

### Constants ###
CSR_VERSION = 0x0
CERT_VERSION = 0x2
CRL_VERSION = 0x1

def build_certification_request_info(
        subject: rfc5280.Name,
        requested_extensions: list[rfc5280.Extension | None],
        public_key_bytes: bytes
) -> rfc2986.CertificationRequestInfo:
    ### Extensions ###
    ext_req_attribute = rfc2985.SingleAttribute()
    ext_req_attribute_val = ExtensionsRequest()
    extensions = rfc5280.Extensions()

    for ext in requested_extensions:
        if ext is not None:
            extensions.append(ext)

    ### Attributes ###
    attributes = rfc2986.Attributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    if len(extensions) > 0:
        ext_req_attribute_val.append(extensions)
        ext_req_attribute["type"] = univ.ObjectIdentifier("1.2.840.113549.1.9.14")
        ext_req_attribute['values'] = ext_req_attribute_val
        attributes.append(ext_req_attribute)

    ### CSR info ###
    csr_info = rfc2986.CertificationRequestInfo()
    csr_info["version"] = CSR_VERSION
    csr_info['subject'] = subject
    csr_info['subjectPKInfo'] = der_decoder(public_key_bytes, asn1Spec=rfc5280.SubjectPublicKeyInfo())[0]
    csr_info['attributes'] = attributes

    return csr_info

def _build_subject_key_identifier_extension(public_key_bytes: bytes) -> rfc5280.Extension:
    skid_extension = rfc5280.Extension()
    skid_key_hash = hashlib.sha1(public_key_bytes).digest()
    skid_extension["extnID"] = x509.OID_SUBJECT_KEY_IDENTIFIER.dotted_string
    skid_extension["extnValue"] = der_encoder(rfc5280.SubjectKeyIdentifier(skid_key_hash))

    return skid_extension

def _build_authority_key_identifier_extension(key_identifier: bytes) -> rfc5280.Extension:
    akid = rfc5280.AuthorityKeyIdentifier()
    akid['keyIdentifier'] = key_identifier
    akid_extension = rfc5280.Extension()
    akid_extension["extnID"] = x509.OID_AUTHORITY_KEY_IDENTIFIER.dotted_string
    akid_extension["extnValue"] = der_encoder(akid)

    return akid_extension

def build_revoked_certificate_entry(
        serial: rfc5280.CertificateSerialNumber,
        revocation_time: rfc5280.Time,
        revocation_reason: rfc5280.CRLReason
) -> RevokedCertificateEntry:
    revoked_certificate_entry = RevokedCertificateEntry()
    revoked_certificate_entry["userCertificate"] = serial
    revoked_certificate_entry["revocationDate"] = revocation_time

    crl_extensions = rfc5280.Extensions()
    revocation_reason_ext = rfc5280.Extension()
    revocation_reason_ext['extnID'] = x509.OID_CRL_REASON.dotted_string
    revocation_reason_ext['extnValue'] = univ.OctetString(der_encoder(revocation_reason))
    crl_extensions.append(revocation_reason_ext)

    revoked_certificate_entry['crlEntryExtensions'] = crl_extensions

    return revoked_certificate_entry

def _akid_ext_from_issuer(issuer: rfc5280.Certificate) -> rfc5280.Extension:
    issuer_skid_ext = get_extension_by_oid_from_certificate(issuer, x509.OID_SUBJECT_KEY_IDENTIFIER.dotted_string)
    if not issuer_skid_ext:
        raise CryptoException(f"Issuer certificate does not contain subject key identifier extension.")

    akid_key_identifier = der_decoder(issuer_skid_ext['extnValue'], asn1Spec=rfc5280.SubjectKeyIdentifier())[0].asOctets()
    return _build_authority_key_identifier_extension(akid_key_identifier)

def build_tbs_certificate(
        issuer_cert: rfc5280.Certificate | None,
        csr: rfc2986.CertificationRequest,
        days: int,
        signature_algorithm: rfc5280.AlgorithmIdentifier,
        *,
        serial: int | None = None,
        additional_extensions: list[rfc5280.Extension | None] | None = None,
        now: datetime | None = None,
) -> rfc5280.TBSCertificate:
    csr_info = csr.getComponentByName("certificationRequestInfo")

    tbs_cert = rfc5280.TBSCertificate()

    ### Validity ###
    validity = rfc5280.Validity()

    now = now or datetime.now(timezone.utc)

    not_before_time = now - timedelta(hours=1)
    not_after_time = now + timedelta(days=days)

    validity["notBefore"] = get_ans1_time(not_before_time)
    validity["notAfter"] = get_ans1_time(not_after_time)

    ### Extensions ###
    crt_extensions = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

    ### Subject Key Identifier ###
    skid_extension = _build_subject_key_identifier_extension(der_encoder(csr_info.getComponentByName("subjectPKInfo")))
    crt_extensions.append(skid_extension)

    ### Authority Key Identifier ###
    if issuer_cert:
        crt_extensions.append(_akid_ext_from_issuer(issuer_cert))

    ### Requested Extensions ###
    csr_requested_extension_oids = []

    csr_attributes: rfc2986.Attributes = csr_info.getComponentByName("attributes")
    ext_req_attr = next(filter(lambda attr: attr['type'] == univ.ObjectIdentifier("1.2.840.113549.1.9.14"), csr_attributes), None)
    if ext_req_attr:
        requested_extensions = ext_req_attr['values']
        for ext_oct in requested_extensions:
            for ext in der_decoder(ext_oct, asn1Spec=rfc5280.Extensions())[0]:
                csr_requested_extension_oids.append(str(ext['extnID']))
                crt_extensions.append(ext)

    # Attach crldp from issuer when present and not requested with CSR
    crldp_ext = None
    if issuer_cert and str(ExtensionOID.CRL_DISTRIBUTION_POINTS.dotted_string) not in csr_requested_extension_oids:
        crldp_ext = get_extension_by_oid_from_certificate(issuer_cert, ExtensionOID.CRL_DISTRIBUTION_POINTS.dotted_string)
        if crldp_ext:
            crt_extensions.append(crldp_ext)

    for extension in (additional_extensions or []):
        if extension is None or str(extension['extnID']) in csr_requested_extension_oids:
            continue

        if str(extension['extnID']) == ExtensionOID.CRL_DISTRIBUTION_POINTS.dotted_string and crldp_ext is not None:
            continue

        crt_extensions.append(extension)

    if serial is None:
        serial = generate_random_serial()

    tbs_cert["issuer"] = issuer_cert["tbsCertificate"]["subject"] if issuer_cert else csr_info["subject"]
    tbs_cert["version"] = CERT_VERSION
    tbs_cert["serialNumber"] = rfc5280.CertificateSerialNumber(serial)
    tbs_cert["signature"] = signature_algorithm
    tbs_cert["validity"] = validity
    tbs_cert["subject"] = csr_info["subject"]
    tbs_cert["subjectPublicKeyInfo"] = csr_info["subjectPKInfo"]
    tbs_cert["extensions"] = crt_extensions

    return tbs_cert

def build_tbs_cert_list(
        issuer_cert: rfc5280.Certificate,
        days: int,
        signature_algorithm: rfc5280.AlgorithmIdentifier,
        revoked_certificate_entries: list[RevokedCertificateEntry],
        *,
        crl_number: int | None = None,
        now: datetime | None = None,
        aia_ext: rfc5280.Extension | None = None,
) -> rfc5280.TBSCertList:
    now = now or datetime.now(timezone.utc)

    tbs_crl = rfc5280.TBSCertList()

    signature_algorithm = signature_algorithm
    revoked_certificates = RevokedCertificates()

    if crl_number is None:
        # CRL number needs to be monotonically increasing
        crl_number = time.time()

    for revoked_cert in revoked_certificate_entries:
        revoked_certificates.append(revoked_cert)

    crl_extensions = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))

    if aia_ext:
        crl_extensions.append(aia_ext)

    ### Akid ###
    crl_extensions.append(_akid_ext_from_issuer(issuer_cert))

    ### CRL Number ###
    crl_number_ext = rfc5280.Extension()
    crl_number_ext['extnID'] = ExtensionOID.CRL_NUMBER.dotted_string
    crl_number_ext['critical'] = False
    crl_number_ext['extnValue'] = der_encoder(rfc5280.CRLNumber(crl_number))
    crl_extensions.append(crl_number_ext)

    tbs_crl['version'] = CRL_VERSION
    tbs_crl["signature"] = signature_algorithm
    tbs_crl["issuer"] = issuer_cert["tbsCertificate"]["subject"]
    tbs_crl["thisUpdate"] = get_ans1_time(now - timedelta(hours=1))
    tbs_crl["nextUpdate"] = get_ans1_time(now + timedelta(days=days))
    tbs_crl["revokedCertificates"] = revoked_certificates
    tbs_crl['crlExtensions'] = crl_extensions

    return tbs_crl
