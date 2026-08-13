"""Shared fixtures: a real signing key, real JWTs, and the real policy bundle.

Nothing here stubs `JwtUser.from_token` or the policy engine. Both are
`celine-sdk` code with their own tests, and a mocked validator proves only that
the mock was called — it cannot catch a token this service *should* have
rejected. What is worth exercising in this repo is its own wiring: header
parsing, the subject-type derivation that decides whether a token is judged as a
service or a user, the mosquitto `acc` bitmask, the per-action evaluation loop,
and the `policies/*.rego` bundle that ships in the image.

So tokens are genuinely signed and genuinely verified. The only seam is the
JWKS *fetch*, which would otherwise need a live Keycloak: `_get_jwks_client` is
replaced by a stub handing back the test public key, which leaves the
signature, `exp`, `iss` and `sub` checks fully in force.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

repo_root = Path(__file__).resolve().parents[1]
src = repo_root / "src"
if src.exists() and str(src) not in sys.path:
    sys.path.insert(0, str(src))

REPO_ROOT = repo_root
POLICIES_DIR = repo_root / "policies"
CLIENTS_YAML = repo_root / "clients.yaml"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip `CELINE_*` and `ENV` from the environment.

    Every settings class in this repo reads env vars, so a developer's shell
    (or a `.env` exported before `task test`) would otherwise decide what the
    tests assert — an issuer or a policies directory pointing somewhere else.

    `ENV` matters doubly: `task test` exports `ENV=dev` for the whole taskfile,
    and it is a POSIX shell variable besides, so the production-mode tests would
    silently assert nothing when run through the task runner.
    """
    import os

    for key in list(os.environ):
        if key.startswith("CELINE_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("ENV", raising=False)


# ---------------------------------------------------------------------------
# JWT: a real keypair, real signatures, stubbed JWKS delivery
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def signing_key() -> dict[str, Any]:
    """An RSA keypair, generated once for the whole session."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {
        "private_pem": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        "public_key": key.public_key(),
    }


@pytest.fixture(scope="session")
def foreign_key() -> bytes:
    """A second private key nobody trusts — for the wrong-signer case."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@pytest.fixture(autouse=True)
def patched_jwks(signing_key: dict[str, Any]):
    """Serve the test public key instead of fetching Keycloak's JWKS.

    Only the network call is replaced. `jwt.decode` still runs in full, so a
    token signed by another key, expired, or issued by another realm fails here
    exactly as it would in production.
    """

    class _SigningKey:
        key = signing_key["public_key"]

    class _JwksClient:
        def get_signing_key_from_jwt(self, token: str) -> _SigningKey:
            return _SigningKey()

    import celine.sdk.auth.jwt as sdk_jwt

    with patch.object(sdk_jwt, "_get_jwks_client", lambda uri: _JwksClient()):
        yield


DEFAULT_ISSUER = "http://keycloak.celine.localhost/realms/celine"


@pytest.fixture
def mint_token(signing_key: dict[str, Any]) -> Callable[..., str]:
    """Return a factory for signed RS256 tokens.

    `scope` is the space-separated string Keycloak issues, not a list, so the
    splitting in `_extract_subject_from_token` is exercised rather than
    bypassed. `groups` entries may carry the leading slash Keycloak emits.
    """

    def _mint(
        sub: str = "svc-test",
        *,
        scope: str | None = None,
        groups: list[str] | None = None,
        organization: dict[str, Any] | None = None,
        issuer: str = DEFAULT_ISSUER,
        expires_in: int = 3600,
        private_pem: bytes | None = None,
        **extra_claims: Any,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "sub": sub,
            "iss": issuer,
            "iat": now,
            "exp": now + expires_in,
        }
        if scope is not None:
            claims["scope"] = scope
        if groups is not None:
            claims["groups"] = groups
        if organization is not None:
            claims["organization"] = organization
        claims.update(extra_claims)

        return jwt.encode(
            claims,
            private_pem or signing_key["private_pem"],
            algorithm="RS256",
            headers={"kid": "test-key"},
        )

    return _mint


@pytest.fixture
def bearer(mint_token: Callable[..., str]) -> Callable[..., dict[str, str]]:
    """`mint_token`, wrapped as a ready-to-send Authorization header."""

    def _bearer(*args: Any, **kwargs: Any) -> dict[str, str]:
        return {"Authorization": f"Bearer {mint_token(*args, **kwargs)}"}

    return _bearer


# ---------------------------------------------------------------------------
# The service, with the policies it actually ships
# ---------------------------------------------------------------------------


@pytest.fixture
def policy_engine():
    """The shipped `policies/` bundle, loaded through the SDK engine."""
    from celine.sdk.policies import PolicyEngine

    engine = PolicyEngine(policies_dir=POLICIES_DIR)
    engine.load()
    return engine


@pytest.fixture
def app(monkeypatch: pytest.MonkeyPatch):
    """The real FastAPI app, pointed at the repo's policy bundle.

    Via the env var rather than by patching settings: `create_app` constructs
    its own `MqttAuthSettings`, and this is the same path a container uses.
    """
    monkeypatch.setenv("CELINE_POLICIES_DIR", str(POLICIES_DIR))

    from celine.mqtt_auth.main import create_app

    return create_app()


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient

    return TestClient(app)
