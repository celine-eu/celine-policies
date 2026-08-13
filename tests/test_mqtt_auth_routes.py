"""The three endpoints mosquitto-go-auth calls, end to end.

Real signed tokens, the real policy bundle, the real app — see `conftest`. The
broker treats any non-200 as a deny, so the status code *is* the security
boundary and every case below asserts it rather than only the body.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from celine.mqtt_auth.config import MqttAuthSettings
from celine.mqtt_auth.routes import (
    _acc_to_actions,
    _extract_subject_from_token,
    _get_token_from_header,
)
from celine.sdk.policies import SubjectType

# A topic the shipped policy accepts as well-formed: celine/<service>/<resource>/...
TOPIC = "celine/pipelines/runs/job-123"

POLICIES_DIR = str(Path(__file__).resolve().parents[1] / "policies")


# ---------------------------------------------------------------------------
# acc bitmask
# ---------------------------------------------------------------------------


class TestAccToActions:
    """mosquitto sends a bitmask; the policy is written against verbs.

    A mask that decoded to the wrong verb would authorise a publish against a
    read grant, so each bit is pinned individually.
    """

    def test_read_bit(self):
        assert _acc_to_actions(1) == ["read"]

    def test_publish_bit(self):
        assert _acc_to_actions(2) == ["publish"]

    def test_subscribe_bit(self):
        assert _acc_to_actions(4) == ["subscribe"]

    def test_combined_bits_yield_every_action(self):
        assert set(_acc_to_actions(3)) == {"read", "publish"}
        assert set(_acc_to_actions(7)) == {"read", "publish", "subscribe"}

    def test_zero_yields_nothing(self):
        """Empty, not a placeholder verb: the caller turns this into a deny."""
        assert _acc_to_actions(0) == []

    def test_unknown_bits_are_ignored(self):
        """acc=8 (mosquitto's write-to-subscription) grants nothing here."""
        assert _acc_to_actions(8) == []


# ---------------------------------------------------------------------------
# Authorization header
# ---------------------------------------------------------------------------


class TestGetTokenFromHeader:
    def test_extracts_bearer_token(self):
        assert _get_token_from_header("Bearer abc.def.ghi") == "abc.def.ghi"

    def test_scheme_is_case_insensitive(self):
        """Real clients send `bearer`; rejecting them would be an outage."""
        assert _get_token_from_header("bearer abc.def.ghi") == "abc.def.ghi"

    def test_surrounding_whitespace_is_stripped(self):
        assert _get_token_from_header("Bearer  abc.def  ") == "abc.def"

    @pytest.mark.parametrize(
        "header",
        [None, "", "abc.def.ghi", "Basic dXNlcjpwYXNz", "Bearer"],
    )
    def test_anything_else_yields_no_token(self, header: str | None):
        assert _get_token_from_header(header) is None


# ---------------------------------------------------------------------------
# Subject extraction — decides which half of the policy applies
# ---------------------------------------------------------------------------


class TestSubjectExtraction:
    """`type` selects the rule family: `service_allowed` vs `user_allowed`.

    Get it wrong and a token is judged against scopes it was never granted, or
    against groups it does not have — so the derivation is pinned directly.
    """

    @pytest.fixture
    def settings(self) -> MqttAuthSettings:
        return MqttAuthSettings()

    def test_groups_make_it_a_user(self, mint_token, settings):
        subject = _extract_subject_from_token(
            mint_token("u-1", groups=["/pipelines.runs.read"]), settings
        )
        assert subject is not None
        assert subject.type is SubjectType.USER
        # the leading slash Keycloak emits is stripped, or no group ever matches
        assert subject.groups == ["pipelines.runs.read"]

    def test_scopes_without_groups_make_it_a_service(self, mint_token, settings):
        subject = _extract_subject_from_token(
            mint_token("svc-pipelines", scope="pipelines.runs.read"), settings
        )
        assert subject is not None
        assert subject.type is SubjectType.SERVICE
        assert subject.scopes == ["pipelines.runs.read"]

    def test_groups_win_over_scopes(self, mint_token, settings):
        """A human token that also carries scopes is still judged as a user."""
        subject = _extract_subject_from_token(
            mint_token("u-2", scope="pipelines.admin", groups=["/viewers"]), settings
        )
        assert subject is not None
        assert subject.type is SubjectType.USER

    def test_neither_makes_it_anonymous(self, mint_token, settings):
        """No scope and no group: valid signature, zero authority."""
        subject = _extract_subject_from_token(mint_token("nobody"), settings)
        assert subject is not None
        assert subject.type is SubjectType.ANONYMOUS
        assert subject.scopes == []
        assert subject.groups == []

    def test_space_separated_scope_string_is_split(self, mint_token, settings):
        subject = _extract_subject_from_token(
            mint_token("svc-x", scope="a.read b.write c.admin"), settings
        )
        assert subject is not None
        assert subject.scopes == ["a.read", "b.write", "c.admin"]

    def test_org_groups_are_picked_up(self, mint_token, settings):
        """REC membership arrives under `organization.<alias>.groups`.

        Users provisioned by `sync-users` get their groups this way, so missing
        them would deny every REC operator.
        """
        subject = _extract_subject_from_token(
            mint_token(
                "u-3",
                organization={"greenland": {"groups": ["/pipelines.runs.read"]}},
            ),
            settings,
        )
        assert subject is not None
        assert subject.type is SubjectType.USER
        assert subject.groups == ["pipelines.runs.read"]

    def test_a_list_valued_scope_claim_is_taken_as_is(self, mint_token, settings):
        """Not every issuer emits the space-separated string Keycloak does."""
        subject = _extract_subject_from_token(
            mint_token("svc-x", scope=["a.read", "b.write"]), settings
        )
        assert subject is not None
        assert subject.scopes == ["a.read", "b.write"]

    def test_a_scope_claim_of_another_type_is_ignored(self, mint_token, settings):
        """Junk in the claim yields no authority, rather than a 500."""
        subject = _extract_subject_from_token(mint_token("svc-x", scope=42), settings)
        assert subject is not None
        assert subject.scopes == []
        assert subject.type is SubjectType.ANONYMOUS

    @pytest.mark.parametrize("token", ["", "   ", "not-a-jwt", "a.b.c"])
    def test_malformed_tokens_return_none(self, token: str, settings):
        """None, never an exception — the routes turn it into a 403."""
        assert _extract_subject_from_token(token, settings) is None


# ---------------------------------------------------------------------------
# POST /user — authentication
# ---------------------------------------------------------------------------


class TestUserEndpoint:
    def test_a_valid_token_authenticates(self, client: TestClient, bearer):
        response = client.post("/user", headers=bearer("svc-pipelines"))

        assert response.status_code == 200
        assert response.json() == {"ok": True, "reason": "authenticated"}

    def test_authentication_does_not_require_any_authority(
        self, client: TestClient, bearer
    ):
        """`/user` answers "is this a real token", not "may it do anything".

        Authorization is `/acl`'s job — a scopeless token still connects.
        """
        assert client.post("/user", headers=bearer("nobody")).status_code == 200

    def test_a_missing_header_is_rejected(self, client: TestClient):
        response = client.post("/user")

        assert response.status_code == 403
        assert response.json() == {"ok": False, "reason": "missing token"}

    def test_a_non_bearer_header_is_rejected(self, client: TestClient, mint_token):
        response = client.post(
            "/user", headers={"Authorization": mint_token("svc-x")}
        )

        assert response.status_code == 403
        assert response.json()["reason"] == "missing token"

    def test_an_expired_token_is_rejected(self, client: TestClient, bearer):
        response = client.post("/user", headers=bearer("svc-x", expires_in=-3600))

        assert response.status_code == 403
        assert response.json()["reason"] == "invalid credentials"

    def test_a_token_from_another_issuer_is_rejected(self, client: TestClient, bearer):
        """Same signing key, wrong realm — `iss` is checked, so this fails."""
        response = client.post(
            "/user", headers=bearer("svc-x", issuer="http://evil.example/realms/x")
        )

        assert response.status_code == 403
        assert response.json()["reason"] == "invalid credentials"

    def test_a_token_signed_by_another_key_is_rejected(
        self, client: TestClient, bearer, foreign_key: bytes
    ):
        """The signature check is live; this is not a mocked validator."""
        response = client.post(
            "/user", headers=bearer("svc-x", private_pem=foreign_key)
        )

        assert response.status_code == 403
        assert response.json()["reason"] == "invalid credentials"

    def test_a_token_without_sub_is_rejected(self, client: TestClient, mint_token):
        """No subject means nothing to log or authorise against."""
        token = mint_token(None, scope="pipelines.admin")
        response = client.post("/user", headers={"Authorization": f"Bearer {token}"})

        assert response.status_code == 403
        assert response.json()["reason"] == "invalid credentials"

    def test_garbage_is_rejected_without_a_500(self, client: TestClient):
        response = client.post("/user", headers={"Authorization": "Bearer not.a.jwt"})

        assert response.status_code == 403


# ---------------------------------------------------------------------------
# POST /acl — authorization
# ---------------------------------------------------------------------------


class TestAclEndpoint:
    """Every request here runs the shipped rego, not a stubbed decision."""

    def _acl(
        self,
        client: TestClient,
        headers: dict[str, str],
        topic: str = TOPIC,
        acc: int = 4,
    ):
        return client.post(
            "/acl",
            headers=headers,
            json={"clientid": "mosq-1", "topic": topic, "acc": acc},
        )

    def test_a_service_subscribes_with_the_matching_read_scope(
        self, client: TestClient, bearer
    ):
        response = self._acl(
            client, bearer("svc-pipelines", scope="pipelines.runs.read"), acc=4
        )

        assert response.status_code == 200
        assert response.json() == {"ok": True, "reason": "authorized"}

    def test_a_read_scope_does_not_grant_publish(self, client: TestClient, bearer):
        """publish maps to the `.write` verb; a read grant must not cover it."""
        response = self._acl(
            client, bearer("svc-pipelines", scope="pipelines.runs.read"), acc=2
        )

        assert response.status_code == 403
        assert response.json()["ok"] is False

    def test_a_service_publishes_with_the_write_scope(self, client: TestClient, bearer):
        response = self._acl(
            client, bearer("svc-pipelines", scope="pipelines.runs.write"), acc=2
        )

        assert response.status_code == 200

    def test_another_services_scope_does_not_carry_over(
        self, client: TestClient, bearer
    ):
        """The topic names the service; holding `dt.*` cannot reach pipelines."""
        response = self._acl(
            client, bearer("svc-dt", scope="dt.runs.read dt.admin"), acc=4
        )

        assert response.status_code == 403

    def test_a_user_subscribes_via_group_membership(self, client: TestClient, bearer):
        response = self._acl(
            client, bearer("u-1", groups=["/pipelines.runs.read"]), acc=4
        )

        assert response.status_code == 200

    def test_an_authenticated_token_with_no_authority_is_denied(
        self, client: TestClient, bearer
    ):
        """Authentication is not authorization: this token passes `/user`."""
        response = self._acl(client, bearer("nobody"), acc=4)

        assert response.status_code == 403

    def test_a_combined_mask_requires_every_verb(self, client: TestClient, bearer):
        """acc=3 is read+publish. A read-only grant must not satisfy it.

        The loop denies on the first failing action, so a policy that allowed
        one verb and refused the other must still produce a deny.
        """
        response = self._acl(
            client, bearer("svc-pipelines", scope="pipelines.runs.read"), acc=3
        )

        assert response.status_code == 403

    def test_a_combined_mask_passes_when_all_verbs_are_granted(
        self, client: TestClient, bearer
    ):
        response = self._acl(
            client,
            bearer("svc-pipelines", scope="pipelines.runs.read pipelines.runs.write"),
            acc=3,
        )

        assert response.status_code == 200

    def test_every_action_in_the_mask_is_evaluated(
        self, client: TestClient, app, bearer
    ):
        """A short-circuit on the first *allow* would skip the publish check."""
        calls: list[str] = []
        engine = app.state.engine
        original = engine.evaluate_decision

        def spy(*, policy_package: str, policy_input: Any):
            calls.append(policy_input.action.name)
            return original(policy_package=policy_package, policy_input=policy_input)

        engine.evaluate_decision = spy

        self._acl(
            client,
            bearer("svc-pipelines", scope="pipelines.runs.read pipelines.runs.write"),
            acc=3,
        )

        assert set(calls) == {"read", "publish"}

    def test_evaluation_stops_at_the_first_denial(
        self, client: TestClient, app, bearer
    ):
        """Once denied, the remaining verbs are moot — and must not be asked.

        acc=7 with a read-only grant: `subscribe` passes (it maps to the `read`
        verb), `publish` fails, and the third check never happens.
        """
        calls: list[str] = []
        engine = app.state.engine
        original = engine.evaluate_decision

        def spy(*, policy_package: str, policy_input: Any):
            calls.append(policy_input.action.name)
            return original(policy_package=policy_package, policy_input=policy_input)

        engine.evaluate_decision = spy

        response = self._acl(
            client, bearer("svc-pipelines", scope="pipelines.runs.read"), acc=7
        )

        assert response.status_code == 403
        assert calls == ["subscribe", "publish"]

    @pytest.mark.parametrize("acc", [0, 8])
    def test_a_mask_carrying_no_known_verb_is_denied(
        self, client: TestClient, bearer, acc: int
    ):
        """Nothing to check must fail closed, not fall through to allow."""
        response = self._acl(
            client, bearer("svc-pipelines", scope="pipelines.admin"), acc=acc
        )

        assert response.status_code == 403
        assert response.json()["reason"] == "invalid acc mask"

    def test_the_denial_reason_from_the_policy_reaches_the_broker(
        self, client: TestClient, bearer
    ):
        """The reason is the only diagnostic in the broker log."""
        response = self._acl(
            client,
            bearer("svc-pipelines", scope="pipelines.runs.read"),
            topic="celine/pipelines/#",
            acc=4,
        )

        assert response.status_code == 403
        assert response.json()["reason"] == "service-level wildcard denied"

    def test_a_missing_header_is_rejected(self, client: TestClient):
        response = self._acl(client, {})

        assert response.status_code == 403
        assert response.json()["reason"] == "missing token"

    def test_an_expired_token_is_rejected(self, client: TestClient, bearer):
        response = self._acl(
            client,
            bearer("svc-pipelines", scope="pipelines.admin", expires_in=-3600),
        )

        assert response.status_code == 403
        assert response.json()["reason"] == "invalid credentials"

    def test_an_unparseable_body_fails_loudly(self, client: TestClient, bearer):
        """Documents current behaviour: a 500, not a deny.

        mosquitto-go-auth treats any non-200 as a deny either way, so this is
        fail-closed — but the status says "our fault", which is the honest
        signal when the broker sends a body this service cannot read.
        """
        response = client.post(
            "/acl",
            headers=bearer("svc-pipelines", scope="pipelines.admin"),
            json={"topic": "celine/pipelines/runs/j"},  # no clientid, no acc
        )

        assert response.status_code == 500

    def test_the_request_id_header_is_accepted(self, client: TestClient, bearer):
        """Correlates a broker decision with the service log line."""
        response = client.post(
            "/acl",
            headers={
                **bearer("svc-pipelines", scope="pipelines.runs.read"),
                "X-Request-ID": "req-abc",
            },
            json={"clientid": "mosq-1", "topic": TOPIC, "acc": 4},
        )

        assert response.status_code == 200

    def test_a_failing_engine_denies_rather_than_erroring(
        self, client: TestClient, app, bearer
    ):
        """A policy bundle blowing up must not become an open door."""

        def boom(**_: Any):
            raise RuntimeError("regorus exploded")

        app.state.engine.evaluate_decision = boom

        response = self._acl(
            client, bearer("svc-pipelines", scope="pipelines.admin"), acc=4
        )

        assert response.status_code == 403
        assert response.json() == {"ok": False, "reason": "check failed"}


# ---------------------------------------------------------------------------
# POST /superuser — bypasses every ACL check, so it is checked narrowly
# ---------------------------------------------------------------------------


class TestSuperuserEndpoint:
    def _superuser(self, client: TestClient, headers: dict[str, str]):
        return client.post("/superuser", headers=headers, json={"username": "any"})

    def test_the_configured_scope_grants_superuser(self, client: TestClient, bearer):
        response = self._superuser(client, bearer("svc-admin", scope="mqtt.admin"))

        assert response.status_code == 200
        assert response.json() == {"ok": True, "reason": "superuser"}

    def test_the_admin_group_grants_superuser(self, client: TestClient, bearer):
        response = self._superuser(client, bearer("u-admin", groups=["/admin"]))

        assert response.status_code == 200
        assert response.json()["ok"] is True

    def test_the_mqtt_admin_group_grants_superuser(self, client: TestClient, bearer):
        response = self._superuser(client, bearer("u-admin", groups=["/mqtt.admin"]))

        assert response.status_code == 200

    def test_an_ordinary_service_is_not_a_superuser(self, client: TestClient, bearer):
        response = self._superuser(
            client, bearer("svc-pipelines", scope="pipelines.runs.read")
        )

        assert response.status_code == 403
        assert response.json() == {"ok": False, "reason": "not superuser"}

    def test_a_service_admin_scope_is_not_superuser(self, client: TestClient, bearer):
        """`pipelines.admin` is broad inside one service, not across the broker."""
        response = self._superuser(
            client, bearer("svc-pipelines", scope="pipelines.admin")
        )

        assert response.status_code == 403

    def test_an_admin_scope_is_not_the_admin_group(self, client: TestClient, bearer):
        """`mqtt.admin` as a *group* on a token that also has scopes.

        Groups make the subject a user; the group check must still fire.
        """
        response = self._superuser(
            client,
            bearer("u-1", scope="pipelines.runs.read", groups=["/mqtt.admin"]),
        )

        assert response.status_code == 200

    def test_a_missing_header_is_rejected(self, client: TestClient):
        response = self._superuser(client, {})

        assert response.status_code == 403
        assert response.json()["reason"] == "missing token"

    def test_an_invalid_token_is_rejected(self, client: TestClient):
        response = self._superuser(client, {"Authorization": "Bearer not.a.jwt"})

        assert response.status_code == 403
        assert response.json()["reason"] == "invalid credentials"

    def test_the_superuser_scope_is_configurable(
        self, client: TestClient, app, bearer
    ):
        """Deployments rename it; the endpoint must read settings, not a literal."""
        app.state.settings = app.state.settings.model_copy(
            update={"mqtt_superuser_scope": "broker.root"}
        )

        assert self._superuser(
            client, bearer("svc-admin", scope="broker.root")
        ).status_code == 200
        assert self._superuser(
            client, bearer("svc-admin", scope="mqtt.admin")
        ).status_code == 403


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


class TestAppWiring:
    def test_health_reports_the_loaded_bundle(self, client: TestClient):
        """A service that answered with zero policies would deny everything."""
        body = client.get("/health").json()

        assert body["status"] == "healthy"
        assert body["policies_loaded"] is True
        assert body["policy_count"] > 0
        assert "celine.mqtt.acl" in body["packages"]
        assert "celine.scopes" in body["packages"]

    def test_the_engine_dependency_is_overridden_at_startup(self, app):
        """Unwired, `get_engine` raises NotImplementedError on every request."""
        from celine.mqtt_auth.routes import get_engine, get_settings

        assert get_engine in app.dependency_overrides
        assert get_settings in app.dependency_overrides

    def _acl(self, client: TestClient, headers: dict[str, str], topic: str = TOPIC):
        return client.post(
            "/acl", headers=headers, json={"clientid": "m", "topic": topic, "acc": 4}
        )

    def test_repeated_broker_checks_hit_the_cache(
        self, client: TestClient, app, bearer
    ):
        """The broker re-checks on every message, so the cache has to work.

        Each request carries a fresh `request_id` and timestamp in
        `environment`; if those reached the cache key nothing would ever hit and
        the TTL would be decoration.
        """
        headers = bearer("svc-pipelines", scope="pipelines.runs.read")
        for _ in range(3):
            assert self._acl(client, headers).status_code == 200

        stats = app.state.engine.cache_stats
        assert stats["hits"] == 2
        assert stats["size"] == 1

    def test_a_cached_allow_is_not_served_to_another_subject(
        self, client: TestClient, bearer
    ):
        """Same topic, same action, different token — the key must include it.

        A cache keyed on resource and action alone would hand this second,
        unauthorised client the first one's allow.
        """
        assert self._acl(
            client, bearer("svc-pipelines", scope="pipelines.runs.read")
        ).status_code == 200
        assert self._acl(client, bearer("nobody")).status_code == 403

    def test_caching_can_be_disabled(
        self, monkeypatch: pytest.MonkeyPatch, bearer
    ):
        """A cached decision outlives a revoked grant, so it must be switchable."""
        monkeypatch.setenv("CELINE_POLICIES_DIR", POLICIES_DIR)
        monkeypatch.setenv("CELINE_POLICIES_CACHE_ENABLED", "false")

        from celine.mqtt_auth.main import create_app

        app = create_app()
        client = TestClient(app)
        headers = bearer("svc-pipelines", scope="pipelines.runs.read")
        for _ in range(3):
            assert self._acl(client, headers).status_code == 200

        assert app.state.engine.cache_stats["hits"] == 0
