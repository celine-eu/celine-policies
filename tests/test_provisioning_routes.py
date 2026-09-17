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
    AccountNotFound,
    CommunityNotFound,
    DisableResult,
    Divergence,
    HasPassword,
    InvitationCooldown,
    InvitationResult,
    MemberNotFound,
    NoEmail,
    NoPassword,
    ProvisioningError,
    ReconcileResult,
    RegistryUnavailable,
    SendFailed,
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
            username="ex-00001",
            keycloak_id="uuid-1",
            created=True,
            invitation=self.invitation if invite else "not_requested",
        )

    async def send_invitation(self, *, community, key, intent):
        self.calls.append(("send_invitation", community, key, intent))
        if self.raises:
            raise self.raises
        return InvitationResult(
            username="ex-00001",
            keycloak_id="uuid-1",
            invitation="sent",
            actions=("UPDATE_PASSWORD", "VERIFY_EMAIL"),
            lifespan=604800,
        )

    async def disable(self, *, community, key):
        self.calls.append(("disable", community, key))
        if self.raises:
            raise self.raises
        return DisableResult(username="ex-00001", keycloak_id="uuid-1", changed=True)

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
INVITE = {"intent": "invitation"}
RESET = {"intent": "password_reset"}


# --- authentication and authorisation ------------------------------------


def test_no_token_is_refused(app_with):
    client, service = app_with(scopes=WRITE)

    response = client.put("/participants/example-rec/ex-00001", json=BODY)

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "missing_token"
    assert service.calls == []


def test_a_token_that_does_not_verify_is_refused(app_with):
    client, service = app_with(scopes=WRITE, valid_token=False)

    response = client.put(
        "/participants/example-rec/ex-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_token"
    assert service.calls == []


def test_a_valid_token_without_the_scope_is_forbidden(app_with):
    """401 and 403 are different on purpose: renew a credential, or ask for a
    grant."""
    client, service = app_with(scopes=("onboarding.admin",))

    response = client.put(
        "/participants/example-rec/ex-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "insufficient_scope"
    assert "provisioning.participants.write" in response.json()["detail"]["message"]
    assert service.calls == []


def test_the_write_scope_does_not_authorise_a_sweep(app_with):
    """Provisioning one member somebody asked about and sweeping a whole
    community are different grants, and holding one is not holding the other."""
    client, _ = app_with(scopes=WRITE)

    response = client.post(
        "/reconcile/example-rec", headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 403


def test_the_reconcile_scope_does_not_authorise_an_upsert(app_with):
    client, _ = app_with(scopes=RECONCILE)

    response = client.put(
        "/participants/example-rec/ex-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 403


@pytest.mark.parametrize(
    "method,path",
    [
        ("put", "/participants/example-rec/ex-00001"),
        ("post", "/participants/example-rec/ex-00001/invitation"),
        ("post", "/participants/example-rec/ex-00001/disable"),
        ("post", "/reconcile/example-rec"),
    ],
)
def test_provisioning_admin_satisfies_every_route(app_with, method, path):
    """The admin-override rule `clients.yaml` documents, honoured here rather
    than inherited — a scope check that quietly differs from the convention is
    worse than one that repeats it."""
    client, _ = app_with(scopes=ADMIN)

    body = BODY if method == "put" else INVITE if path.endswith("/invitation") else None
    response = getattr(client, method)(
        path, json=body, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 200


# --- the upsert -----------------------------------------------------------


def test_the_upsert_returns_the_uuid_under_the_name_onboarding_stores(app_with):
    """`user_id` on the wire is the Keycloak uuid; `username` is what becomes
    the registry's `Member.user_id`. The two names collide across the seam and
    this is where the mapping happens."""
    client, _ = app_with(scopes=WRITE)

    response = client.put(
        "/participants/example-rec/ex-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert response.json() == {
        "user_id": "uuid-1",
        "username": "ex-00001",
        "created": True,
        "invitation": "not_requested",
        "invited": False,
    }


def test_a_body_with_no_email_is_refused_before_anything_is_written(app_with):
    client, service = app_with(scopes=WRITE)

    response = client.put(
        "/participants/example-rec/ex-00001", json={}, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 422
    assert service.calls == []


def test_the_upsert_passes_locale_and_invite_through(app_with):
    client, service = app_with(scopes=WRITE, service=FakeService(invitation="sent"))

    response = client.put(
        "/participants/example-rec/ex-00001",
        json={**BODY, "locale": "es", "invite": True},
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 200
    assert response.json()["invitation"] == "sent"
    assert response.json()["invited"] is True
    assert service.calls == [
        ("ensure_participant", "example-rec", "ex-00001", BODY["email"], "es", True)
    ]


def test_locale_and_invite_default_to_nothing_and_false(app_with):
    client, service = app_with(scopes=WRITE)

    client.put(
        "/participants/example-rec/ex-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert service.calls[0][4:] == (None, False)


@pytest.mark.parametrize("locale", ["fr", "IT", "", "es-ES"])
def test_a_locale_the_themes_do_not_carry_is_refused_with_422(app_with, locale):
    """Keycloak stores any value and silently falls back to the realm default
    for one it has no bundle for (measured, Phase 1), so the check is here."""
    client, service = app_with(scopes=WRITE)

    response = client.put(
        "/participants/example-rec/ex-00001",
        json={**BODY, "locale": locale},
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 422
    assert service.calls == []


@pytest.mark.parametrize(
    "invitation",
    [
        "has_password",
        "no_email",
        "not_on_dev_list",
        "account_disabled",
        "cooldown",
        "send_failed",
    ],
)
def test_an_invitation_that_was_not_sent_is_still_a_200_with_the_reason(
    app_with, invitation
):
    """O3 (requester, 2026-09-14): an approval is never blocked by its email,
    and the operator is told why nothing went out."""
    client, _ = app_with(scopes=WRITE, service=FakeService(invitation=invitation))

    response = client.put(
        "/participants/example-rec/ex-00001",
        json={**BODY, "invite": True},
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 200
    assert response.json()["invitation"] == invitation
    assert response.json()["invited"] is False


def test_a_keycloak_failure_on_the_upsert_is_502_with_its_code(app_with):
    """The account step itself failing, as opposed to its email."""
    client, _ = app_with(
        scopes=WRITE, service=FakeService(raises=ProvisioningError("account vanished"))
    )

    response = client.put(
        "/participants/example-rec/ex-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 502
    assert response.json() == {
        "detail": {"code": "provisioning_failed", "message": "account vanished"}
    }


def test_the_upsert_is_always_200_so_a_retry_looks_like_the_same_call(app_with):
    client, _ = app_with(scopes=WRITE)

    response = client.put(
        "/participants/example-rec/ex-00001", json=BODY, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 200


# --- the lifecycle calls --------------------------------------------------


def test_an_invitation_reports_what_was_emailed_and_carries_no_credential(app_with):
    client, service = app_with(scopes=WRITE)

    response = client.post(
        "/participants/example-rec/ex-00001/invitation",
        json=INVITE,
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "user_id": "uuid-1",
        "username": "ex-00001",
        "invitation": "sent",
        "actions": ["UPDATE_PASSWORD", "VERIFY_EMAIL"],
        "lifespan": 604800,
    }
    assert "password" not in response.text.replace("UPDATE_PASSWORD", "")
    assert service.calls == [("send_invitation", "example-rec", "ex-00001", "invitation")]


@pytest.mark.parametrize("intent", ["invitation", "password_reset"])
def test_the_intent_reaches_the_service_as_given(app_with, intent):
    client, service = app_with(scopes=WRITE)

    response = client.post(
        "/participants/example-rec/ex-00001/invitation",
        json={"intent": intent},
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 200
    assert service.calls == [("send_invitation", "example-rec", "ex-00001", intent)]


@pytest.mark.parametrize(
    "body",
    [None, {}, {"intent": "reset"}, {"intent": ""}, {"intent": "INVITATION"}],
    ids=["no-body", "empty", "unknown", "blank", "wrong-case"],
)
def test_an_invitation_without_a_known_intent_is_refused_before_the_service(
    app_with, body
):
    """The intent is required, with no default (requester, 2026-09-14, A2): a
    default would be the service choosing the email for the caller."""
    client, service = app_with(scopes=WRITE)

    response = client.post(
        "/participants/example-rec/ex-00001/invitation",
        json=body,
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 422
    assert service.calls == []


NOT_FOUND = [
    (CommunityNotFound("The registry has no community 'example-rec'"), "community_not_found"),
    (MemberNotFound("example-rec has no active member 'x'"), "member_not_found"),
    (AccountNotFound("example-rec/x is registered as 'x', and the realm has no such account"), "account_not_found"),
]


@pytest.mark.parametrize("path", ["invitation", "disable"])
@pytest.mark.parametrize("error,code", NOT_FOUND, ids=[c for _, c in NOT_FOUND])
def test_every_404_says_which_thing_is_missing(app_with, path, error, code):
    """One status, three causes. The code tells them apart, so a consumer never
    has to parse the sentence or ask the registry again (requester, 2026-09-14:
    "the more informative the better"). The sentence stays, for a person."""
    client, _ = app_with(scopes=WRITE, service=FakeService(raises=error))

    response = client.post(
        f"/participants/example-rec/x/{path}",
        json=INVITE if path == "invitation" else None,
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": {"code": code, "message": str(error)}}


def test_a_sweep_of_a_community_the_registry_does_not_have_is_404(app_with):
    client, _ = app_with(
        scopes=RECONCILE,
        service=FakeService(raises=CommunityNotFound("The registry has no community 'nowhere'")),
    )

    response = client.post("/reconcile/nowhere", headers={"Authorization": "Bearer x"})

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "community_not_found"


def test_an_invitation_to_a_disabled_account_is_409(app_with):
    client, _ = app_with(
        scopes=WRITE, service=FakeService(raises=AccountDisabled("example-rec/x is disabled"))
    )

    response = client.post(
        "/participants/example-rec/x/invitation", json=INVITE, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 409
    assert response.json() == {
        "detail": {"code": "account_disabled", "message": "example-rec/x is disabled"}
    }


CONFLICTS = [
    (HasPassword("example-rec/x already has a password"), INVITE, "has_password"),
    (NoPassword("example-rec/x has no password to reset"), RESET, "no_password"),
    (NoEmail("example-rec/x has no email address"), INVITE, "no_email"),
    (NoEmail("example-rec/x has no email address"), RESET, "no_email"),
]


@pytest.mark.parametrize(
    "error,body,code", CONFLICTS, ids=[f"{c}-{b['intent']}" for _, b, c in CONFLICTS]
)
def test_an_intent_the_account_does_not_fit_or_no_address_is_409_with_its_code(
    app_with, error, body, code
):
    """A consumer names the other button from the code, never from the
    sentence, and no `Retry-After`: pressing the other button works at once."""
    client, _ = app_with(scopes=WRITE, service=FakeService(raises=error))

    response = client.post(
        "/participants/example-rec/x/invitation", json=body, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 409
    assert response.json() == {"detail": {"code": code, "message": str(error)}}
    assert "retry-after" not in response.headers


def test_an_invitation_within_the_cooldown_is_429_with_retry_after(app_with):
    client, _ = app_with(
        scopes=WRITE,
        service=FakeService(raises=InvitationCooldown("too soon", retry_after=42)),
    )

    response = client.post(
        "/participants/example-rec/x/invitation", json=INVITE, headers={"Authorization": "Bearer x"}
    )

    assert response.status_code == 429
    assert response.headers["retry-after"] == "42"
    assert response.json() == {"detail": {"code": "cooldown", "message": "too soon"}}


@pytest.mark.parametrize(
    "error,code",
    [
        (RegistryUnavailable("registry unreachable"), "registry_unavailable"),
        (SendFailed("Keycloak did not email example-rec/ex-00001"), "send_failed"),
        (ProvisioningError("something else"), "provisioning_failed"),
    ],
)
def test_a_registry_or_keycloak_failure_is_502_with_its_code(app_with, error, code):
    """It is a dependency that failed, not this service refusing — an operator
    reading a 500 goes to the wrong logs. `send_failed` starts no cooldown, so
    it is worth retrying."""
    client, _ = app_with(scopes=WRITE, service=FakeService(raises=error))

    response = client.post(
        "/participants/example-rec/ex-00001/invitation",
        json=INVITE,
        headers={"Authorization": "Bearer x"},
    )

    assert response.status_code == 502
    assert response.json() == {"detail": {"code": code, "message": str(error)}}
    assert "retry-after" not in response.headers


# --- the sweep ------------------------------------------------------------


def test_a_clean_sweep_reports_what_it_did(app_with):
    client, _ = app_with(scopes=RECONCILE)

    response = client.post("/reconcile/example-rec", headers={"Authorization": "Bearer x"})

    assert response.status_code == 200
    assert response.json() == {
        "community": "example-rec",
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
                    key="ex-00001",
                    username="ex-00001",
                    kind="not in the REC organization",
                    detail="no `organization` claim",
                ),
            ),
        )

    service.reconcile = diverging
    client, _ = app_with(scopes=RECONCILE, service=service)

    response = client.post("/reconcile/example-rec", headers={"Authorization": "Bearer x"})

    assert response.status_code == 500
    detail = response.json()["detail"]
    assert detail["code"] == "reconcile_diverged"
    assert "1 member" in detail["message"]
    # the report is still the body, where the SDK reads it
    assert detail["divergences"][0]["key"] == "ex-00001"
    assert detail["community"] == "example-rec"


# --- the shape of the surface --------------------------------------------


def _openapi() -> dict:
    from celine.provisioning.main import create_app

    return create_app().openapi()


def test_the_contract_lists_the_new_invitation_codes():
    """A contract change: a generated client with the old enum raises on these,
    so the SDK is regenerated before this service is deployed."""
    schemas = _openapi()["components"]["schemas"]

    assert schemas["InvitationOutcome"]["enum"] == [
        "not_requested",
        "sent",
        "has_password",
        "not_on_dev_list",
        "account_disabled",
        "cooldown",
        "send_failed",
        "no_email",
    ]
    # the route's own 200 outcomes are unchanged: the rest are status codes there
    assert schemas["InvitationSendOutcome"]["enum"] == ["sent", "not_on_dev_list"]


def test_the_invitation_route_requires_an_intent_body():
    """1.3.0: a breaking change for a caller that posted no body, which is why
    the SDK's `send_invitation` gains a required `intent`."""
    spec = _openapi()
    operation = spec["paths"]["/participants/{community}/{key}/invitation"]["post"]

    assert operation["requestBody"]["required"] is True
    ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    request = spec["components"]["schemas"][ref.rsplit("/", 1)[-1]]
    assert request["required"] == ["intent"]
    assert spec["components"]["schemas"]["InvitationIntent"]["enum"] == [
        "invitation",
        "password_reset",
    ]
    assert spec["info"]["version"] == "1.3.0"


def test_every_route_declares_its_errors_with_the_shared_body():
    spec = _openapi()
    expected = {
        ("/participants/{community}/{key}", "put"): {"401", "403", "502"},
        ("/participants/{community}/{key}/invitation", "post"): {"401", "403", "404", "409", "429", "502"},
        ("/participants/{community}/{key}/disable", "post"): {"401", "403", "404", "502"},
        ("/reconcile/{community}", "post"): {"401", "403", "404", "502"},
    }

    for (path, method), statuses in expected.items():
        responses = spec["paths"][path][method]["responses"]
        for status_code in statuses:
            ref = responses[status_code]["content"]["application/json"]["schema"]["$ref"]
            assert ref == "#/components/schemas/ErrorResponse", (path, status_code)

    detail = spec["components"]["schemas"]["ErrorDetail"]
    assert set(detail["required"]) == {"code", "message"}
    # a string, not an enum: a new code must not break a generated client
    assert detail["properties"]["code"]["type"] == "string"
    assert "enum" not in detail["properties"]["code"]


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
