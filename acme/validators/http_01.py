"""HTTP-01 challenge validator for ACME."""

import asyncio
import aiohttp
from aiohttp import (
    ClientConnectionError,
    ClientResponseError,
    ClientPayloadError,
    ClientSSLError,
    TooManyRedirects
)

from acme.config import acme_logger, Http01
from acme.db import (
    ChallengeEntity,
    ChallengeStatus,
    AuthzStatus,
    OrderStatus,
    ErrorEntity
)


class Http01Validator:
    """Validator for HTTP-01 ACME challenges."""

    def __init__(self, controller, challenge: ChallengeEntity, config: Http01):
        self.controller = controller
        self.challenge = challenge

        self.port = config.port
        self.follow_redirect = config.follow_redirect
        self.timeout_seconds = config.timeout_seconds
        self.retries = config.retries
        self.retry_delay_seconds = config.retry_delay_seconds

    async def get_session(self) -> aiohttp.ClientSession:
        """Create an aiohttp session."""
        timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)

        return aiohttp.ClientSession(
            timeout=timeout,
            raise_for_status=False
        )

    async def _fetch_with_retries(self, session, url):
        last_exc = None
        for attempt in range(1, self.retries + 1):
            try:
                async with session.get(url) as response:
                    text = await response.text()
                    return response.status, text
            except (
                    asyncio.TimeoutError,
                    ClientConnectionError,
                    ClientPayloadError,
                    ClientSSLError,
                    TooManyRedirects,
            ) as exc:
                last_exc = exc
                acme_logger.warning(
                    "HTTP-01 attempt %s/%s failed: %s",
                    attempt, self.retries, exc
                )
                if attempt < self.retries:
                    await asyncio.sleep(self.retry_delay_seconds)

        raise last_exc

    async def validate(self):
        """Validate the HTTP-01 challenge."""
        acme_logger.info(
            "Validating challenge %s with HTTP-01.", self.challenge.id
        )

        token = self.challenge.key_authorization.split(".")[0]
        validation_url = (
            f"http://{self.challenge.authz.identifier_value}:{self.port}" # noqa
            f"/.well-known/acme-challenge/{token}"
        )

        error = None
        error_detail = None

        async with await self.get_session() as session:
            self.challenge.status = ChallengeStatus.PROCESSING
            self.challenge = self.controller.database.save_to_db(self.challenge)

            try:
                status, body = await self._fetch_with_retries(
                    session, validation_url
                )

                body = body.strip()

                if status != 200 or body != self.challenge.key_authorization:
                    error = "incorrectResponse"
                    error_detail = (
                        f"Invalid response from {validation_url}: "
                        f"{status} {body}"
                    )

                else:
                    self.challenge.status = ChallengeStatus.VALID
                    self.challenge.authz.status = AuthzStatus.VALID
                    self.challenge = self.controller.database.save_to_db(
                        self.challenge
                    )
                    self.challenge.authz = self.controller.database.save_to_db(
                        self.challenge.authz
                    )

            except asyncio.TimeoutError as exc:
                error = "connection"
                error_detail = (
                    "Timed out waiting for response, this is most likely "
                    "due to a firewall blocking the request."
                )
                acme_logger.exception(exc)

            except ClientSSLError as exc:
                error = "connection"
                error_detail = f"SSL error when trying to validate challenge: {exc}"
                acme_logger.exception(exc)

            except ClientResponseError as exc:
                error = "connection"
                error_detail = (
                    f"HTTP error when trying to validate challenge: "
                    f"{exc.status} {exc.message}"
                )
                acme_logger.exception(exc)

            except Exception as exc:  # pylint: disable=broad-exception-caught
                error = "connection"
                error_detail = (
                    f"Unknown error when trying to validate challenge: "
                    f"{exc.__class__.__name__}: {exc}"
                )
                acme_logger.exception(exc)

        if error:
            self.challenge.status = ChallengeStatus.INVALID
            self.challenge.authz.status = AuthzStatus.INVALID
            self.challenge.authz.order.status = OrderStatus.INVALID

            error_entity = ErrorEntity(
                type=error,
                detail=error_detail,
                title="Failed to validate challenge."
            )
            self.controller.database.save_to_db(error_entity)

            self.challenge = self.controller.database.save_to_db(self.challenge)
            self.challenge.authz.error = error_entity
            self.challenge.authz = self.controller.database.save_to_db(
                self.challenge.authz
            )
            self.challenge.authz.order = self.controller.database.save_to_db(
                self.challenge.authz.order
            )
