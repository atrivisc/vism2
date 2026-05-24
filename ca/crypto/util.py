import secrets
from datetime import datetime

from cryptography import x509
from cryptography.hazmat._oid import SignatureAlgorithmOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from pyasn1.type import univ, useful
from pyasn1_modules import rfc5280

_signature_algorithm_map: dict[tuple[type, str], str] = {
    (rsa.RSAPublicKey, 'SHA256'): SignatureAlgorithmOID.RSA_WITH_SHA256.dotted_string,
    (rsa.RSAPublicKey, 'SHA384'): SignatureAlgorithmOID.RSA_WITH_SHA384.dotted_string,
    (rsa.RSAPublicKey, 'SHA512'): SignatureAlgorithmOID.RSA_WITH_SHA512.dotted_string,
    (ec.EllipticCurvePublicKey, 'SHA256'): SignatureAlgorithmOID.ECDSA_WITH_SHA256.dotted_string,
    (ec.EllipticCurvePublicKey, 'SHA384'): SignatureAlgorithmOID.ECDSA_WITH_SHA384.dotted_string,
    (ec.EllipticCurvePublicKey, 'SHA512'): SignatureAlgorithmOID.ECDSA_WITH_SHA512.dotted_string,
}

def _resolve_key_type(public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey) -> type:
    if isinstance(public_key, rsa.RSAPublicKey):
        return rsa.RSAPublicKey
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return ec.EllipticCurvePublicKey
    raise KeyError(type(public_key))

def get_algorithm_identifier(public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey, hash_algorithm_name: str) -> rfc5280.AlgorithmIdentifier:
    algorithm_identifier = rfc5280.AlgorithmIdentifier()
    algorithm_oid = _signature_algorithm_map[(_resolve_key_type(public_key), hash_algorithm_name)]
    algorithm_identifier["algorithm"] = univ.ObjectIdentifier(algorithm_oid)
    return algorithm_identifier

def get_extension_by_oid_from_certificate(cert: rfc5280.Certificate, oid: str) -> rfc5280.Extension | None:
    return next(
        filter(
            lambda ext: str(ext['extnID']) == oid, cert['tbsCertificate']['extensions']
        ),
        None
    )

def generate_random_serial() -> int:
    return secrets.randbelow(2**159 - 2**63) + 2**63

def asn1_time_to_datetime(asn1_time: rfc5280.Time) -> datetime:
    chosen = asn1_time.getName()
    if chosen == 'utcTime':
        return asn1_time['utcTime'].asDateTime
    elif chosen == 'generalTime':
        return asn1_time['generalTime'].asDateTime
    else:
        raise ValueError(f"Time CHOICE has no active component (got {chosen!r})")

def get_ans1_time(dt: datetime) -> rfc5280.Time:
    time = rfc5280.Time()

    if dt.year > 2049:
        time["generalTime"] = useful.GeneralizedTime.fromDateTime(dt)
    else:
        time["utcTime"] = useful.UTCTime.fromDateTime(dt)

    return time

def csr_pem_to_der(csr_pem: str) -> bytes:
    return x509.load_pem_x509_csr(csr_pem.encode("utf-8")).public_bytes(serialization.Encoding.DER)

def csr_der_to_pem(csr_der: bytes) -> str:
    return x509.load_der_x509_csr(csr_der).public_bytes(serialization.Encoding.PEM).decode("utf-8")

def crt_pem_to_der(crt_pem: str) -> bytes:
    return x509.load_pem_x509_certificate(crt_pem.encode("utf-8")).public_bytes(serialization.Encoding.DER)

def crt_der_to_pem(crt_der: bytes) -> str:
    return x509.load_der_x509_certificate(crt_der).public_bytes(serialization.Encoding.PEM).decode("utf-8")

def crt_der_chain_to_pem_chain(crt_ders: list[bytes]) -> str:
    return "".join(
        x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode("utf-8") + "\n"
        for der in crt_ders
    )
