import hashlib
from datetime import datetime, timezone, timedelta

from cryptography import x509
from pyasn1.type import univ, tag
from pyasn1_modules import rfc2985, rfc5280, rfc2986

from ca.asn1 import ExtensionsRequest, RevokedCertificates, RevokedCertificateEntry
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from ca.crypto.util import get_algorithm_identifier, get_ans1_time, get_extension_by_oid_from_certificate, generate_random_serial
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

    ext_req_attribute_val.append(extensions)

    ext_req_attribute["type"] = univ.ObjectIdentifier("1.2.840.113549.1.9.14")
    ext_req_attribute['values'] = ext_req_attribute_val

    ### Attributes ###
    attributes = rfc2986.Attributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
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

def build_tbs_certificate(
        issuer_cert: rfc5280.Certificate | None,
        csr: rfc2986.CertificationRequest,
        days: int,
        signature_algorithm: rfc5280.AlgorithmIdentifier,
        *,
        serial: int | None = None,
        authority_info_access_ext: rfc5280.Extension | None = None,
        crl_distribution_points_ext: rfc5280.Extension | None = None,
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
    extensions = rfc5280.Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))

    ### Subject Key Identifier ###
    skid_extension = _build_subject_key_identifier_extension(csr_info.getComponentByName("subjectPKInfo").asOctets())
    extensions.append(skid_extension)

    ### Authority Key Identifier ###
    if issuer_cert:
        issuer_skid_ext = get_extension_by_oid_from_certificate(issuer_cert, x509.OID_SUBJECT_KEY_IDENTIFIER.dotted_string)
        if not issuer_skid_ext:
            raise CryptoException(f"Issuer certificate does not contain subject key identifier extension.")

        akid_key_identifier = der_decoder(issuer_skid_ext['extnValue'], asn1Spec=rfc5280.SubjectKeyIdentifier())[0].asOctets()
        akid_ext = _build_authority_key_identifier_extension(akid_key_identifier)
        extensions.append(akid_ext)

    ### Requested Extensions ###
    csr_attributes: rfc2986.Attributes = csr_info.getComponentByName("attributes")
    ext_req_attr = next(filter(lambda attr: attr['type'] == univ.ObjectIdentifier("1.2.840.113549.1.9.14"), csr_attributes), None)
    if ext_req_attr:
        requested_extensions = ext_req_attr['values']
        for ext_oct in requested_extensions:
            for ext in der_decoder(ext_oct, asn1Spec=rfc5280.Extensions())[0]:
                extensions.append(ext)

    ### Authority Information Access ###
    if not authority_info_access_ext and issuer_cert:
        authority_info_access_ext = get_extension_by_oid_from_certificate(issuer_cert, x509.OID_AUTHORITY_INFORMATION_ACCESS.dotted_string)
    elif not authority_info_access_ext and not issuer_cert:
        raise CryptoException("Issuer certificate not provided and no authority information access extension found in CSR.")

    if authority_info_access_ext:
        extensions.append(authority_info_access_ext)

    ### CRL Distribution Points ###
    if not crl_distribution_points_ext and issuer_cert:
        crl_distribution_points_ext = get_extension_by_oid_from_certificate(issuer_cert, x509.OID_CRL_DISTRIBUTION_POINTS.dotted_string)
    elif not crl_distribution_points_ext and not issuer_cert:
        raise CryptoException("Issuer certificate not provided and no CRL distribution points extension found in CSR.")

    if crl_distribution_points_ext:
        extensions.append(crl_distribution_points_ext)

    if serial is None:
        serial = generate_random_serial()

    tbs_cert["issuer"] = issuer_cert["tbsCertificate"]["subject"] if issuer_cert else csr_info["subject"]
    tbs_cert["version"] = CERT_VERSION
    tbs_cert["serialNumber"] = rfc5280.CertificateSerialNumber(serial)
    tbs_cert["signature"] = signature_algorithm
    tbs_cert["validity"] = validity
    tbs_cert["subject"] = csr_info["subject"]
    tbs_cert["subjectPublicKeyInfo"] = csr_info["subjectPKInfo"]
    tbs_cert["extensions"] = extensions

    return tbs_cert

def build_tbs_cert_list(
        issuer_cert: rfc5280.Certificate,
        days: int,
        signature_algorithm: rfc5280.AlgorithmIdentifier,
        revoked_certificate_entries: list[RevokedCertificateEntry],
        *,
        now: datetime | None = None
) -> rfc5280.TBSCertList:
    now = now or datetime.now(timezone.utc)

    tbs_crl = rfc5280.TBSCertList()

    signature_algorithm = signature_algorithm
    revoked_certificates = RevokedCertificates()

    for revoked_cert in revoked_certificate_entries:
        revoked_certificates.append(revoked_cert)

    tbs_crl['version'] = CRL_VERSION
    tbs_crl["signature"] = signature_algorithm

    tbs_crl["issuer"] = issuer_cert["tbsCertificate"]["subject"]
    tbs_crl["thisUpdate"] = get_ans1_time(now - timedelta(hours=1))
    tbs_crl["nextUpdate"] = get_ans1_time(now + timedelta(days=days))
    tbs_crl["revokedCertificates"] = revoked_certificates

    return tbs_crl