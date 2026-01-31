import pytest
from fastapi import HTTPException

from celine.policies.auth.jwt import JWTValidator
from celine.policies.routes import deps


class FakeValidator(JWTValidator):
    def __init__(self, claims=None, exc=None):
        self._claims = claims
        self._exc = exc

    def validate(self, token: str):
        if self._exc:
            raise self._exc
        return self._claims or {}


@pytest.mark.asyncio
async def test_get_subject_returns_none_without_header(monkeypatch):
    subj = await deps.get_subject(authorization=None, jwt_validator=FakeValidator())
    assert subj is None


@pytest.mark.asyncio
async def test_get_subject_rejects_bad_header(monkeypatch):
    with pytest.raises(HTTPException) as e:
        await deps.get_subject(authorization="Bad xxx", jwt_validator=FakeValidator())
    assert e.value.status_code == 401


@pytest.mark.asyncio
async def test_get_subject_valid(monkeypatch):
    claims = {"sub": "u1", "iat": 1, "exp": 2, "iss": "x", "groups": ["g"]}
    subj = await deps.get_subject(
        authorization="Bearer token", jwt_validator=FakeValidator(claims=claims)
    )
    assert subj is not None
    assert subj.id == "u1"
