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

    def delete(self, obj_type: Type[Base], *criterion: ColumnExpressionArgument[bool]):
        with self._get_session() as session:
            session.query(obj_type).filter(*criterion).delete()

    def nonce_cleanup(self):
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=30)
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

    def pop_nonce(self, nonce: str, account: AccountEntity | None) -> NonceEntity | None:
        if account:
            nonce_entity = self.get(NonceEntity, NonceEntity.nonce == nonce, NonceEntity.account_id == account.id)
        else:
            nonce_entity = self.get(NonceEntity, NonceEntity.nonce == nonce)

        if not nonce_entity:
            return None

        self.delete(NonceEntity, NonceEntity.id == nonce_entity.id)
        return nonce_entity

    def get_orders_by_account_kid(
            self,
            account_kid: str
    ) -> Optional[list[OrderEntity]]:
        """Get all orders for an account by account kid."""
        return self.get(AccountEntity, AccountEntity.kid == account_kid, multiple=True)

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
