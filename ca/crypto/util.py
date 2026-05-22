import secrets
from datetime import datetime

from cryptography.hazmat._oid import SignatureAlgorithmOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from pyasn1.type import univ, useful
from pyasn1_modules import rfc5280

_signature_algorithm_map: dict[tuple[type[rsa.RSAPublicKey], str] | tuple[type[ec.EllipticCurvePublicKey], str], str] = {
    (rsa.RSAPublicKey, 'SHA256'): SignatureAlgorithmOID.RSA_WITH_SHA256.dotted_string,
    (rsa.RSAPublicKey, 'SHA384'): SignatureAlgorithmOID.RSA_WITH_SHA384.dotted_string,
    (rsa.RSAPublicKey, 'SHA512'): SignatureAlgorithmOID.RSA_WITH_SHA512.dotted_string,
    (ec.EllipticCurvePublicKey, 'SHA256'): SignatureAlgorithmOID.ECDSA_WITH_SHA256.dotted_string,
    (ec.EllipticCurvePublicKey, 'SHA384'): SignatureAlgorithmOID.ECDSA_WITH_SHA384.dotted_string,
    (ec.EllipticCurvePublicKey, 'SHA512'): SignatureAlgorithmOID.ECDSA_WITH_SHA512.dotted_string,
}

def get_algorithm_identifier(public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey, hash_algorithm_name: str) -> rfc5280.AlgorithmIdentifier:
    algorithm_identifier = rfc5280.AlgorithmIdentifier()
    algorithm_oid = _signature_algorithm_map[(public_key.__class__, hash_algorithm_name)]
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
    return secrets.randbits(159)

def asn1_time_to_datetime(asn1_time: rfc5280.Time) -> datetime:
    if asn1_time['utcTime'].hasValue():
        return asn1_time['utcTime'].asDateTime()
    else:
        return asn1_time['generalTime'].asDateTime()

def get_ans1_time(dt: datetime) -> rfc5280.Time:
    time = rfc5280.Time()

    if dt.year > 2049:
        time["generalTime"] = useful.GeneralizedTime.fromDateTime(dt)
    else:
        time["utcTime"] = useful.UTCTime.fromDateTime(dt)

    return time
