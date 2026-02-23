import hashlib
from operator import getitem
from typing import TypeVar

import pkcs11
from pkcs11 import Attribute, Session, Token, AttributeTypeInvalid, AttributeSensitive, mechanisms
from ca.config import PKCS11Config
from ca.p11.key import PKCS11PrivKey, PKCS11PubKey
from lib.config import shared_logger

ObjectT = TypeVar('ObjectT', bound=pkcs11.Object)

def get_mechanism_for_hash_algorithm(key_type: pkcs11.KeyType, hash_alg: str):
    if key_type == pkcs11.KeyType.RSA:
        return mechanisms.Mechanism.__getitem__(f"{hash_alg.upper()}_RSA_PKCS")
    elif key_type == pkcs11.KeyType.EC:
        return mechanisms.Mechanism.__getitem__(f"ECDSA_{hash_alg.upper()}")
    else:
        return None

class PKCS11Client:
    def __init__(self, config: PKCS11Config):
        self.config = config
        self.p11 = pkcs11.lib(config.lib_path)
        self.token: Token = self.p11.get_token(token_label=config.token_label)

    def _get_raw_object(self, session: Session, obj_class: pkcs11.ObjectClass, label: str) -> ObjectT:
        shared_logger.debug(f"Getting object {obj_class.name} {label}")
        objects = list(session.get_objects({
            pkcs11.Attribute.CLASS: obj_class,
            pkcs11.Attribute.LABEL: label
        }))

        if len(objects) == 0:
            shared_logger.debug(f"Object {obj_class.name} {label} not found.")
            return None
        elif len(objects) > 1:
            raise ValueError(f"Multiple objects found with the label: {label}.")

        return objects[0]

    def _get_key_pair(self, session: Session, privkey: PKCS11PrivKey, pubkey: PKCS11PubKey) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        pubkey = self._get_raw_object(session, pkcs11.ObjectClass.PUBLIC_KEY, pubkey.label)
        privkey = self._get_raw_object(session, pkcs11.ObjectClass.PRIVATE_KEY, privkey.label)
        return pubkey, privkey

    @staticmethod
    def _generate_rsa_keypair(session: Session, priv_key: PKCS11PrivKey, pub_key: PKCS11PubKey) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        shared_logger.debug(f"Generating RSA keypair {priv_key.label}")

        return session.generate_keypair(
            priv_key.key_type, priv_key.key_length,
            private_template=priv_key.template,
            public_template=pub_key.template
        )

    @staticmethod
    def _generate_ec_keypair(session: Session, priv_key: PKCS11PrivKey, pub_key: PKCS11PubKey) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        shared_logger.debug(f"Generating EC keypair {priv_key.label}")

        domain = session.create_domain_parameters(priv_key.key_type, {Attribute.EC_PARAMS: priv_key.ec_params}, local=True)
        return domain.generate_keypair(
            private_template=priv_key.template,
            public_template=pub_key.template
        )

    @staticmethod
    def _get_p11_obj_attributes(obj: pkcs11.Object) -> dict:
        real_attrs = {}
        for attr in Attribute:
            try:
                real_attrs[attr] = getitem(obj, attr.value)
            except AttributeTypeInvalid, ValueError, NotImplementedError, AttributeSensitive:
                pass
        return real_attrs

    def sign_data(self, privkey: PKCS11PrivKey, data: bytes, hash_alg_name: str) -> bytes:
        with self.token.open(rw=True, user_pin=self.config.user_pin) as session:
            privkey_obj = self._get_raw_object(session, pkcs11.ObjectClass.PRIVATE_KEY, privkey.label)
            if privkey_obj is None:
                raise ValueError(f"No private key found with label: {privkey.label}")

            mechanism = get_mechanism_for_hash_algorithm(privkey.key_type, hash_alg_name)
            signature = privkey_obj.sign(data, mechanism=mechanism)

            return signature

    def generate_keypair(self, pub_key: PKCS11PubKey, priv_key: PKCS11PrivKey) -> tuple[PKCS11PubKey, PKCS11PrivKey]:
        with self.token.open(rw=True, user_pin=self.config.user_pin) as session:
            p11_pubkey, p11_privkey = self._get_key_pair(session, priv_key, pub_key)

            if p11_privkey is None:
                if priv_key.key_type == pkcs11.KeyType.RSA:
                    p11_pubkey, p11_privkey = self._generate_rsa_keypair(session, priv_key, pub_key)
                elif priv_key.key_type == pkcs11.KeyType.EC:
                    p11_pubkey, p11_privkey = self._generate_ec_keypair(session, priv_key, pub_key)
                else:
                    raise ValueError(f"Unsupported key type: {priv_key.key_type}")

            return PKCS11PubKey(self._get_p11_obj_attributes(p11_pubkey), pub_key.ec_curve), PKCS11PrivKey(self._get_p11_obj_attributes(p11_privkey))
