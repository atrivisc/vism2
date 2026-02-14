import pkcs11
from pkcs11 import Attribute, Session
from ca.config import PKCS11Config
from ca.p11.key import PKCS11PrivKey, PKCS11PubKey


class PKCS11Client:
    def __init__(self, config: PKCS11Config):
        self.config = config
        self.p11 = pkcs11.lib(config.lib_path)
        self.token = self.p11.get_token(token_label=config.token_label)

    def _get_raw_object(self, session: Session, obj_class: pkcs11.ObjectClass, label: str):
        objects = list(session.get_objects({
            pkcs11.Attribute.CLASS: obj_class,
            pkcs11.Attribute.LABEL: label
        }))

        if len(objects) == 0:
            return None
        elif len(objects) > 1:
            raise ValueError(f"Multiple objects found with the label: {label}.")

        return objects[0]

    def get_raw_object(self, obj_class: pkcs11.ObjectClass, label: str) -> pkcs11.Object | None:
        with self.token.open(user_pin=self.config.user_pin) as session:
            return self._get_raw_object(session, obj_class, label)

    def _generate_rsa_keypair(self, session: Session, priv_key: PKCS11PrivKey, pub_key: PKCS11PubKey) -> None:
        existing_priv_key = self._get_raw_object(session, pkcs11.ObjectClass.PRIVATE_KEY, priv_key.label)

        if existing_priv_key is not None:
            return

        session.generate_keypair(
            priv_key.key_type, priv_key.key_length,
            private_template=priv_key.template,
            public_template=pub_key.template
        )

    def _generate_ec_keypair(self, session: Session, priv_key: PKCS11PrivKey, pub_key: PKCS11PubKey) -> None:
        existing_priv_key = self._get_raw_object(session, pkcs11.ObjectClass.PRIVATE_KEY, priv_key.label)

        if existing_priv_key is not None:
            return

        domain = session.create_domain_parameters(priv_key.key_type, {Attribute.EC_PARAMS: priv_key.ec_params})
        domain.generate_keypair(
            private_template=priv_key.template,
            public_template=pub_key.template
        )

    def generate_keypair(self, priv_key: PKCS11PrivKey, pub_key: PKCS11PubKey) -> None:
        with self.token.open(user_pin=self.config.user_pin) as session:
            if priv_key.key_type == pkcs11.KeyType.RSA:
                self._generate_rsa_keypair(session, priv_key, pub_key)
            elif priv_key.key_type == pkcs11.KeyType.EC:
                self._generate_ec_keypair(session, priv_key, pub_key)
            else:
                raise ValueError(f"Unsupported key type: {priv_key.key_type}")
