from datetime import datetime

from pyasn1.type import univ, namedtype, useful
from pyasn1_modules import rfc5280


class RevokedCertificateEntry(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('userCertificate', rfc5280.CertificateSerialNumber()),
        namedtype.NamedType('revocationDate', rfc5280.Time()),
        namedtype.OptionalNamedType('crlEntryExtensions', rfc5280.Extensions())
    )

class RevokedCertificates(univ.SequenceOf):
    componentType = RevokedCertificateEntry()

class ExtensionsRequest(univ.SetOf):
    componentType = rfc5280.Extensions()

def get_ans1_time(dt: datetime) -> rfc5280.Time:
    time = rfc5280.Time()

    if dt.year > 2049:
        time["generalTime"] = useful.GeneralizedTime.fromDateTime(dt)
    else:
        time["utcTime"] = useful.UTCTime.fromDateTime(dt)

    return time