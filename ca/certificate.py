"""
This module provides an abstraction layer for managing certificates within the Vism CA
controller. It handles certificate issuance, signing, and revocation functionalities,
making it easier to interface with the crypto module, CA database, and other components.

Classes:
    Certificate: Represents a certificate and provides methods for operations such as
                 generating, signing, and managing CRLs.
"""
import pkcs11

from ca.main import VismCA
from ca.config import ca_logger, CertificateConfig, SupportedKeyAlgorithms
from ca.p11.key import PKCS11Key, RSAKey, ECKey


class Certificate:
    """
    Represents a certificate and provides methods for operations such as
    generating, signing, and managing CRLs.
    """

    def __init__(self, controller: 'VismCA', config: CertificateConfig):
        self.controller = controller
        self.config = config

    def generate_keypair(self):
        self.controller.p11_client.generate_keypair(
            self.config.p11_priv_key,
            self.config.p11_pub_key
        )

