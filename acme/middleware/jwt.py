"""Middleware for JWS (JSON Web Signature) validation."""

import json
import logging
from typing import Optional, Callable
from fastapi import Request
from jwcrypto import jws as _jws
from pydantic.dataclasses import dataclass
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from acme.errors import ACMEProblemResponse
from vism_lib.util import b64u_decode, absolute_url
from acme.middleware import AcmeProtectedPayload, AcmeProtectedHeader

logger = logging.getLogger(__name__)

ALLOWED_SIGNATURE_ALGS = [
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
]

@dataclass
class AcmeJWSEnvelope:
    """ACME JWS envelope containing protected header, payload, and signature."""

    encoded_payload: str
    encoded_protected: str
    encoded_signature: str

    payload: Optional[AcmeProtectedPayload] = None
    headers: Optional[AcmeProtectedHeader] = None

    @property
    def is_post_as_get(self):
        """Check if this is a POST-as-GET request (empty payload)."""
        return self.encoded_payload == ""

    def __post_init__(self):
        """Decode and validate the JWS envelope."""
        if self.encoded_payload:
            decoded_payload = json.loads(
                b64u_decode(self.encoded_payload).decode("utf-8")
            )
            self.payload = AcmeProtectedPayload(**decoded_payload)

        if self.encoded_protected:
            decoded = json.loads(
                b64u_decode(self.encoded_protected).decode("utf-8")
            )
            self.headers = AcmeProtectedHeader(**decoded)

        if not self.headers:
            return

        if not self.headers.alg or \
                self.headers.alg not in ALLOWED_SIGNATURE_ALGS:
            problem = ACMEProblemResponse(
                error_type="badSignatureAlgorithm",
                title="Unsupported JWS signature algorithm.",
                detail=(
                    f"JWS \"alg\" must be one of "
                    f"{', '.join(ALLOWED_SIGNATURE_ALGS)}. \"none\" and "
                    f"MAC-based algorithms are not allowed."
                )
            )
            problem.error_json["algorithms"] = ALLOWED_SIGNATURE_ALGS
            raise problem

        if (self.headers.jwk and
                self.headers.jwk.get('kty', None) not in
                ['RSA', 'EC']):
            raise ACMEProblemResponse(
                error_type="badPublicKey",
                title="Invalid JWK key type.",
                detail=(
                    "Account keys must be asymmetric: JWK \"kty\" must "
                    "be RSA or EC."
                )
            )

        if self.headers.kid and self.headers.jwk:
            raise ACMEProblemResponse(
                error_type="malformed",
                title="Client can not provide both kid and jwk."
            )

        if not self.headers.jwk:
            return

        self.verify_signature(
            self.headers.jwk,
            error_type="badPublicKey",
            title="Invalid JWK."
        )

    def verify_signature(
            self,
            key,
            error_type: str = "malformed",
            title: str = "JWS signature verification failed.",
            status_code: int = 400,
    ) -> None:
        try:
            compact = ".".join([
                self.encoded_protected or "",
                self.encoded_payload or "",
                self.encoded_signature or ""
            ])
            j = _jws.JWS()
            j.deserialize(compact)
            j.allowed_algs = ALLOWED_SIGNATURE_ALGS
            j.verify(key)
        except Exception as exc:
            raise ACMEProblemResponse(
                error_type=error_type,
                title=title,
                detail=str(exc),
                status_code=status_code
            ) from exc


class JWSMiddleware(BaseHTTPMiddleware): # pylint: disable=too-few-public-methods
    """Middleware for validating JWS envelopes in ACME requests."""

    def __init__(
            self,
            app,
            skip_paths: Optional[list] = None,
            controller=None,
    ):
        super().__init__(app)
        self.skip_paths = skip_paths or []
        self.controller = controller

    async def dispatch(
            self,
            request: Request,
            call_next: Callable
    ) -> Response:
        """Dispatch request with JWS validation."""
        if any(request.url.path.startswith(path)
               for path in self.skip_paths):
            return await call_next(request)

        if request.method != "POST":
            return await call_next(request)

        try:
            self._validate_content_type(request)
            jws_envelope = await self._parse_jws_envelope(request)
            self._validate_url_header(request, jws_envelope)
        except ACMEProblemResponse as exc:
            return await exc.to_json_response(self.controller)

        request.state.jws_envelope = jws_envelope

        return await call_next(request)

    @staticmethod
    def _validate_content_type(request: Request) -> None:
        content_type = request.headers.get("Content-Type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()

        if media_type != "application/jose+json":
            raise ACMEProblemResponse(
                error_type="malformed",
                title="Invalid Content-Type.",
                detail=(
                    "ACME requests must use Content-Type "
                    "\"application/jose+json\", got "
                    f"\"{content_type or '(none)'}\"."
                ),
                status_code=415
            )

    @staticmethod
    def _validate_url_header(
            request: Request,
            jws_envelope: "AcmeJWSEnvelope"
    ) -> None:
        if not jws_envelope.headers or not jws_envelope.headers.url:
            raise ACMEProblemResponse(
                error_type="unauthorized",
                title="JWS protected header must include a \"url\" field.",
                status_code=403
            )

        path = request.url.path
        if request.url.query:
            path = f"{path}?{request.url.query}"
        expected_url = absolute_url(request, path)

        if jws_envelope.headers.url != expected_url:
            raise ACMEProblemResponse(
                error_type="unauthorized",
                title="JWS \"url\" header does not match the request URL.",
                detail=(
                    f"JWS url header is \"{jws_envelope.headers.url}\" "
                    f"but the request was sent to \"{expected_url}\"."
                ),
                status_code=403
            )

    @staticmethod
    async def _parse_jws_envelope(request: Request) -> AcmeJWSEnvelope:
        """Parse JWS envelope from request body."""
        try:
            envelope_json = await request.json()
            jws_envelope = AcmeJWSEnvelope(
                encoded_protected=envelope_json.get("protected", None),
                encoded_payload=envelope_json.get("payload", None),
                encoded_signature=envelope_json.get("signature", None),
            )
        except Exception as exc:
            raise ACMEProblemResponse(
                error_type="malformed",
                title="Invalid JSON body",
                detail=str(exc)
            ) from exc

        return jws_envelope
