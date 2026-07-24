"""Database interface for VISM ACME operations."""
from datetime import datetime, timezone, timedelta
from typing import Optional, Type
from uuid import UUID

from jwcrypto.jwk import JWK
from sqlalchemy import ColumnExpressionArgument
from vism_lib.database import VismDatabase, Base

from acme.db import (
    OrderEntity,
    AccountEntity,
    AuthzEntity,
    ChallengeEntity,
    JWKEntity
)
from acme.db.nonce import NonceEntity
from acme.config import acme_logger


class VismAcmeDatabase(VismDatabase):
    """Database interface for VISM ACME operations."""

    def get_jwk_by_kid(self, kid: str) -> Optional[JWKEntity]:
        """Retrieve JWK entity by its key ID (kid)."""
        with self._get_session() as session:
            account = self.get_account_by_kid(kid)
            if not account:
                return None

            return session.query(JWKEntity).filter(JWKEntity.id == account.jwk_id).one_or_none()

    def delete(self, obj_type: Type[Base], *criterion: ColumnExpressionArgument[bool]):
        with self._get_session() as session:
            session.query(obj_type).filter(*criterion).delete()

    DEFAULT_NONCE_TTL_SECONDS = 300

    def nonce_cleanup(self, ttl_seconds: int | None = None):
        """Delete expired nonces (best-effort background hygiene)."""
        ttl = ttl_seconds or self.DEFAULT_NONCE_TTL_SECONDS
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=ttl)
        try:
            self.delete(NonceEntity, NonceEntity.created_at < cutoff)
        except Exception as e:
            acme_logger.warning(f"Failed to cleanup nonces: {e}")

    def new_nonce(self, account: AccountEntity | None = None) -> NonceEntity:
        # A bit redundant, but it protects against potential invalid input data like an empty string
        if not account:
            nonce_entity = NonceEntity()
        else:
            nonce_entity = NonceEntity(account=account)

        return self.save_to_db(nonce_entity)

    def pop_nonce(
            self,
            nonce: str,
            account: AccountEntity | None,
            ttl_seconds: int | None = None,
    ) -> NonceEntity | None:
        """Consume a nonce, returning it only if it is valid."""
        if not nonce:
            return None

        nonce_entity = self.get(NonceEntity, NonceEntity.nonce == nonce)
        if not nonce_entity:
            return None

        self.delete(NonceEntity, NonceEntity.id == nonce_entity.id)

        ttl = ttl_seconds or self.DEFAULT_NONCE_TTL_SECONDS
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=ttl)
        if nonce_entity.created_at < cutoff:
            return None

        if nonce_entity.account is not None:
            if account is None or nonce_entity.account.id != account.id:
                return None

        return nonce_entity

    def get_orders_by_account_kid(
            self,
            account_kid: str
    ) -> Optional[list[OrderEntity]]:
        """Get all orders for an account by account kid."""
        account = self.get(AccountEntity, AccountEntity.kid == account_kid)
        if not account:
            return []

        return self.get(OrderEntity, OrderEntity.account_id == account.id, multiple=True)

    def get_order_by_id(self, order_id: str) -> Optional[OrderEntity]:
        """Get an order by its ID."""
        if isinstance(order_id, str):
            order_id = UUID(order_id)

        return self.get(OrderEntity, OrderEntity.id == order_id)

    def get_authz_by_order_id(
            self,
            order_id: str
    ) -> Optional[list[AuthzEntity]]:
        """Get all authorizations for an order."""
        if isinstance(order_id, str):
            order_id = UUID(order_id)

        return self.get(
            AuthzEntity,
            AuthzEntity.order_id == order_id,
            multiple=True
        )

    def get_challenges_by_authz_id(
            self,
            authz_id: str
    ) -> Optional[list[ChallengeEntity]]:
        """Get all challenges for an authorization."""
        if isinstance(authz_id, str):
            authz_id = UUID(authz_id)

        return self.get(
            ChallengeEntity,
            ChallengeEntity.authz_id ==authz_id,
            multiple=True
        )

    def get_authz_by_id(self, authz_id: str) -> Optional[AuthzEntity]:
        """Get an authorization by its ID."""
        if isinstance(authz_id, str):
            authz_id = UUID(authz_id)

        return self.get(AuthzEntity, AuthzEntity.id == authz_id)

    def get_challenge_by_id(
            self,
            challenge_id: str
    ) -> Optional[ChallengeEntity]:
        """Get a challenge by its ID."""
        if isinstance(challenge_id, str):
            challenge_id = UUID(challenge_id)

        return self.get(ChallengeEntity, ChallengeEntity.id == challenge_id)

    def get_account_by_jwk(
            self,
            jwk_data: JWK
    ) -> Optional[AccountEntity]:
        """Get an account by its JWK."""
        jwk_entity = None

        if jwk_data['kty'] == 'oct':
            jwk_entity = self.get(
                JWKEntity,
                JWKEntity.k == jwk_data['k'],
                JWKEntity.kty == jwk_data['kty']
            )
        elif jwk_data['kty'] == 'EC':
            jwk_entity = self.get(
                JWKEntity,
                JWKEntity.crv == jwk_data['crv'],
                JWKEntity.x == jwk_data['x'],
                JWKEntity.y == jwk_data['y'],
                JWKEntity.kty == jwk_data['kty']
            )
        elif jwk_data['kty'] == 'RSA':
            jwk_entity = self.get(
                JWKEntity,
                JWKEntity.n == jwk_data['n'],
                JWKEntity.e == jwk_data['e'],
                JWKEntity.kty == jwk_data['kty']
            )

        if not jwk_entity:
            return None

        return self.get(
            AccountEntity,
            AccountEntity.jwk_id == jwk_entity.id
        )

    def get_account_by_kid(self, kid: str) -> Optional[AccountEntity]:
        """Get an account by its kid (key ID)."""
        return self.get(AccountEntity, AccountEntity.kid == kid)
