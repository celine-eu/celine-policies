import time

import jwt
import pytest
from jwt import PyJWKClientError

from celine.policies.auth.jwt import JWKSCache, JWTValidationError, JWTValidator


class _Key:
    def __init__(self, key):
        self.key = key


def test_jwt_validator_valid_hs256():
    secret = "secret"
    now = int(time.time())
    token = jwt.encode(
        {"sub": "u1", "iat": now, "exp": now + 60, "iss": "issuer"},
        secret,
        algorithm="HS256",
    )

    class FakeJWKS:
        def get_signing_key(self, token: str):
            return _Key(secret)

    v = JWTValidator(jwks_cache=FakeJWKS(), issuer="issuer", audience=None, algorithms=["HS256"])
    claims = v.validate(token)
    assert claims["sub"] == "u1"
    assert claims["iss"] == "issuer"


def test_jwt_validator_invalid_issuer():
    # Ensure token is NOT expired so we actually test issuer validation.
    secret = "secret"
    now = int(time.time())
    token = jwt.encode(
        {"sub": "u1", "iat": now, "exp": now + 60, "iss": "bad"},
        secret,
        algorithm="HS256",
    )

    class FakeJWKS:
        def get_signing_key(self, token: str):
            return _Key(secret)

    v = JWTValidator(jwks_cache=FakeJWKS(), issuer="issuer", audience=None, algorithms=["HS256"])
    with pytest.raises(JWTValidationError) as e:
        v.validate(token)
    assert "Invalid issuer" in str(e.value)


def test_jwks_cache_refresh_on_ttl(monkeypatch):
    created = {"count": 0}

    class FakeClient:
        def __init__(self, uri, cache_keys=True):
            created["count"] += 1
            self._uri = uri

        def get_signing_key_from_jwt(self, token):
            return "KEY"

    import celine.policies.auth.jwt as jwtmod
    monkeypatch.setattr(jwtmod, "PyJWKClient", FakeClient)

    cache = JWKSCache("http://example/jwks", ttl_seconds=0)
    cache.get_signing_key("t")
    cache.get_signing_key("t")
    assert created["count"] >= 2  # ttl=0 forces refresh each call


def test_jwks_cache_refresh_on_unknown_kid(monkeypatch):
    calls = {"n": 0}

    class FakeClient:
        def __init__(self, uri, cache_keys=True):
            pass

        def get_signing_key_from_jwt(self, token):
            calls["n"] += 1
            if calls["n"] == 1:
                raise PyJWKClientError("unknown kid")
            return "KEY"

    import celine.policies.auth.jwt as jwtmod
    monkeypatch.setattr(jwtmod, "PyJWKClient", FakeClient)

    cache = JWKSCache("http://example/jwks", ttl_seconds=3600)
    assert cache.get_signing_key("t") == "KEY"
    assert calls["n"] == 2
