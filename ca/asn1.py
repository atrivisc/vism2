from datetime import datetime

from pyasn1.type import univ, namedtype, useful
from pyasn1_modules import rfc5280
from pyasn1_modules.rfc5280 import CertificateSerialNumber, Time, Extensions


class RevokedCertificateEntry(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('userCertificate', CertificateSerialNumber()),
        namedtype.NamedType('revocationDate', Time()),
        namedtype.OptionalNamedType('crlEntryExtensions', Extensions())
    )

class RevokedCertificates(univ.SequenceOf):
    componentType = RevokedCertificateEntry()


def get_ans1_time(dt: datetime) -> rfc5280.Time:
    time = rfc5280.Time()

    if dt.year > 2049:
        time["generalTime"] = useful.GeneralizedTime.fromDateTime(dt)
    else:
        time["utcTime"] = useful.UTCTime.fromDateTime(dt)

    return time