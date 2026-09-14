"""The provisioning service's route surface: who may call it, and what it answers.

**Ingress restriction is defence in depth, not the control.** The argument that
a service holding `manage-users` and `manage-realm` is safe rests on nothing
outside the network reaching it (ADR-0007) — and a caller *inside* the network
still presents a token and still has to hold the scope. These are the tests that
keep that true, because it is the half a deployment cannot enforce for us.

The service layer is a fake here; what `ProvisioningService` decides is covered
in `test_provisioning_service.py`.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from celine.provisioning import routes as routes_module
from celine.provisioning.config import ProvisioningSettings
from celine.provisioning.routes import get_service, get_settings, router
from celine.provisioning.service import (
    AccountDisabled,
    DisableResult,
    Divergence,
    InvitationCooldown,
    InvitationResult,
    MemberNotFound,
    ProvisioningError,
    ReconcileResult,
    UpsertResult,
)


@dataclass
class FakeUser:
    """Stands in for a verified `JwtUser`."""

    sub: str
    scopes: tuple[str, ...]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


class FakeService:
    def __init__(self, *, raises: Exception | None = None, invitation: str = "not_requested"):
        self.raises = raises
        self.invitation = invitation
        self.calls: list[tuple] = []

    async def ensure_participant(
        self, *, community, key, email, first_name, last_name, locale, invite
    ):
        self.calls.append(("ensure_participant", community, key, email, locale, invite))
        if self.raises:
            raise self.raises
        return UpsertResult(
            username="gl-00001",
            keycloak_id="uuid-1",
            created=True,
            invitation=self.invitation if invite else "not_requested",
        )

    async def send_invitation(self, *, community, key):
        self.calls.append(("send_invitation", community, key))
        if self.raises:
            raise self.raises
        return InvitationResult(
            username="gl-00001",
            keycloak_id="uuid-1",
            invitation="sent",
            actions=("UPDATE_PASSWORD", "VERIFY_EMAIL"),
            lifespan=604800,
        )

    async def disable(self, *, community, key):
        self.calls.append(("disable", community, key))
        if self.raises:
            raise self.raises
        return DisableResult(username="gl-00001", keycloak_id="uuid-1", changed=True)

    async def reconcile(self, community):
        self.calls.append(("reconcile", community))
        if self.raises:
            raise self.raises
        return ReconcileResult(
            community=community, members=2, created=1, existing=1, divergences=()
        )


@pytest.fixture
def app_with(monkeypatch: pytest.MonkeyPatch):
    """An app whose token verification and service are both fakes."""

    def build(*, scopes: tuple[str, ...] = (), service: FakeService | None = None, valid_token: bool = True):
        fake_service = service or FakeService()

        class FakeJwtUser:
            @staticmethod
            def from_token(token, oidc=None):
                if not valid_token:
                    raise ValueError("signature does not verify")
                return FakeUser(sub="svc-onboarding", scopes=scopes)

        monkeypatch.setattr(routes_module, "JwtUser", FakeJwtUser)

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_settings] = lambda: ProvisioningSettings()
        app.dependency_overrides[get_service] = lambda: fake_service
        return TestClient(app, raise_server_exceptions=False), fake_service

    return build


WRITE = ("provisioning.participants.write",)
RECONCILE = ("provisioning.reconcile",)
ADMIN = ("provisioning.admin",)

BODY = {"email": "a.person@example.org"}


# --- authentication and authorisation ------------------------------------


def test_no_token_is_refused(app_with):
    client, service = app_with(scopes=WRITE)

    response = client.put("/participants/greenland/gl-00001", json=BODY)

    assert response.status_code == 401
    assert service.calls == []


def test_a_token_that_does_not_verify_is_refused(app_with):
    client, service = app_with(scopes=WRITE, valid_token=False)

    response = client.put(
        "/participants/greenland/gl-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 401
    assert service.calls == []


def test_a_valid_token_without_the_scope_is_forbidden(app_with):
    """401 and 403 are different on purpose: renew a credential, or ask for a
    grant."""
    client, service = app_with(scopes=("onboarding.admin",))

    response = client.put(
        "/participants/greenland/gl-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 403
    assert "provisioning.participants.write" in response.json()["detail"]
    assert service.calls == []


def test_the_write_scope_does_not_authorise_a_sweep(app_with):
    """Provisioning one member somebody asked about and sweeping a whole
    community are different grants, and holding one is not holding the other."""
    client, _ = app_with(scopes=WRITE)

    response = client.post(
        "/reconcile/greenland", headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 403


def test_the_reconcile_scope_does_not_authorise_an_upsert(app_with):
    client, _ = app_with(scopes=RECONCILE)

    response = client.put(
        "/participants/greenland/gl-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 403


@pytest.mark.parametrize(
    "method,path",
    [
        ("put", "/participants/greenland/gl-00001"),
        ("post", "/participants/greenland/gl-00001/invitation"),
        ("post", "/participants/greenland/gl-00001/disable"),
        ("post", "/reconcile/greenland"),
    ],
)
def test_provisioning_admin_satisfies_every_route(app_with, method, path):
    """The admin-override rule `clients.yaml` documents, honoured here rather
    than inherited — a scope check that quietly differs from the convention is
    worse than one that repeats it."""
    client, _ = app_with(scopes=ADMIN)

    response = getattr(client, method)(
        path, json=BODY if method == "put" else None, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 200


# --- the upsert -----------------------------------------------------------


def test_the_upsert_returns_the_uuid_under_the_name_onboarding_stores(app_with):
    """`user_id` on the wire is the Keycloak uuid; `username` is what becomes
    the registry's `Member.user_id`. The two names collide across the seam and
    this is where the mapping happens."""
    client, _ = app_with(scopes=WRITE)

    response = client.put(
        "/participants/greenland/gl-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert response.json() == {
        "user_id": "uuid-1",
        "username": "gl-00001",
        "created": True,
        "invitation": "not_requested",
        "invited": False,
    }


def test_a_body_with_no_email_is_refused_before_anything_is_written(app_with):
    client, service = app_with(scopes=WRITE)

    response = client.put(
        "/participants/greenland/gl-00001", json={}, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 422
    assert service.calls == []


def test_the_upsert_passes_locale_and_invite_through(app_with):
    client, service = app_with(scopes=WRITE, service=FakeService(invitation="sent"))

    response = client.put(
        "/participants/greenland/gl-00001",
        json={**BODY, "locale": "es", "invite": True},
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 200
    assert response.json()["invitation"] == "sent"
    assert response.json()["invited"] is True
    assert service.calls == [
        ("ensure_participant", "greenland", "gl-00001", BODY["email"], "es", True)
    ]


def test_locale_and_invite_default_to_nothing_and_false(app_with):
    client, service = app_with(scopes=WRITE)

    client.put(
        "/participants/greenland/gl-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert service.calls[0][4:] == (None, False)


@pytest.mark.parametrize("locale", ["fr", "IT", "", "es-ES"])
def test_a_locale_the_themes_do_not_carry_is_refused_with_422(app_with, locale):
    """Keycloak stores any value and silently falls back to the realm default
    for one it has no bundle for (measured, Phase 1), so the check is here."""
    client, service = app_with(scopes=WRITE)

    response = client.put(
        "/participants/greenland/gl-00001",
        json={**BODY, "locale": locale},
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 422
    assert service.calls == []


@pytest.mark.parametrize(
    "invitation", ["has_password", "not_on_dev_list", "account_disabled"]
)
def test_an_invitation_that_was_not_sent_is_still_a_200_with_the_reason(
    app_with, invitation
):
    """O3 (requester, 2026-09-14): an approval is never blocked by its email,
    and the operator is told why nothing went out."""
    client, _ = app_with(scopes=WRITE, service=FakeService(invitation=invitation))

    response = client.put(
        "/participants/greenland/gl-00001",
        json={**BODY, "invite": True},
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 200
    assert response.json()["invitation"] == invitation
    assert response.json()["invited"] is False


def test_the_upsert_is_always_200_so_a_retry_looks_like_the_same_call(app_with):
    client, _ = app_with(scopes=WRITE)

    response = client.put(
        "/participants/greenland/gl-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 200


# --- the lifecycle calls --------------------------------------------------


def test_an_invitation_reports_what_was_emailed_and_carries_no_credential(app_with):
    client, service = app_with(scopes=WRITE)

    response = client.post(
        "/participants/greenland/gl-00001/invitation",
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "user_id": "uuid-1",
        "username": "gl-00001",
        "invitation": "sent",
        "actions": ["UPDATE_PASSWORD", "VERIFY_EMAIL"],
        "lifespan": 604800,
    }
    assert "password" not in response.text.replace("UPDATE_PASSWORD", "")
    assert service.calls == [("send_invitation", "greenland", "gl-00001")]


def test_an_invitation_to_a_member_nobody_has_is_404(app_with):
    client, _ = app_with(
        scopes=WRITE, service=FakeService(raises=MemberNotFound("greenland has no member 'x'"))
    )

    response = client.post(
        "/participants/greenland/x/invitation", headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 404


def test_an_invitation_to_a_disabled_account_is_409(app_with):
    client, _ = app_with(
        scopes=WRITE, service=FakeService(raises=AccountDisabled("greenland/x is disabled"))
    )

    response = client.post(
        "/participants/greenland/x/invitation", headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 409
    assert "disabled" in response.json()["detail"]


def test_an_invitation_within_the_cooldown_is_429_with_retry_after(app_with):
    client, _ = app_with(
        scopes=WRITE,
        service=FakeService(raises=InvitationCooldown("too soon", retry_after=42)),
    )

    response = client.post(
        "/participants/greenland/x/invitation", headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "42"


def test_a_member_nobody_has_is_404_and_not_a_server_error(app_with):
    client, _ = app_with(
        scopes=WRITE, service=FakeService(raises=MemberNotFound("greenland has no member 'x'"))
    )

    response = client.post(
        "/participants/greenland/x/disable", headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 404


def test_a_registry_or_keycloak_failure_is_502(app_with):
    """It is a dependency that failed, not this service refusing — an operator
    reading a 500 goes to the wrong logs."""
    client, _ = app_with(
        scopes=WRITE, service=FakeService(raises=ProvisioningError("registry unreachable"))
    )

    response = client.post(
        "/participants/greenland/gl-00001/invitation",
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 502


# --- the sweep ------------------------------------------------------------


def test_a_clean_sweep_reports_what_it_did(app_with):
    client, _ = app_with(scopes=RECONCILE)

    response = client.post("/reconcile/greenland", headers={"Authorization": "Bearer x"})

    assert response.status_code == 200
    assert response.json() == {
        "community": "greenland",
        "members": 2,
        "created": 1,
        "existing": 1,
        "divergences": [],
    }


def test_a_sweep_that_leaves_a_member_outside_its_organization_fails_loudly(app_with):
    """Everything the check looks at is something this same call claimed to have
    done. A 200 with a list nobody reads is how 10 of 45 members ended up
    outside their own organization with nothing saying so."""
    service = FakeService()

    async def diverging(community):
        return ReconcileResult(
            community=community,
            members=1,
            created=0,
            existing=1,
            divergences=(
                Divergence(
                    key="gl-00001",
                    username="gl-00001",
                    kind="not in the REC organization",
                    detail="no `organization` claim",
                ),
            ),
        )

    service.reconcile = diverging
    client, _ = app_with(scopes=RECONCILE, service=service)

    response = client.post("/reconcile/greenland", headers={"Authorization": "Bearer x"})

    assert response.status_code == 500
    detail = response.json()["detail"]
    assert detail["divergences"][0]["key"] == "gl-00001"


# --- the shape of the surface --------------------------------------------


def test_the_service_exposes_four_routes_and_a_health_check():
    """A route added here by accident converts a realm-wide admin credential
    into an internet-facing one. The count is the review surface."""
    from celine.provisioning.main import create_app

    paths = {
        (r.path, tuple(sorted(r.methods)))
        for r in create_app().routes
        if hasattr(r, "methods") and not r.path.startswith(("/openapi", "/docs", "/redoc"))
    }

    assert paths == {
        ("/participants/{community}/{key}", ("PUT",)),
        ("/participants/{community}/{key}/invitation", ("POST",)),
        ("/participants/{community}/{key}/disable", ("POST",)),
        ("/reconcile/{community}", ("POST",)),
        ("/health", ("GET",)),
    }
