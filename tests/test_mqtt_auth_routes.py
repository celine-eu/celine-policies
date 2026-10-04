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
    """`type` selects the rule family, and it is the token's kind (REQ-0014).

    User or service comes from `is_service_account`, never from whether the token holds
    a group; and no group of either level reaches the subject.
    """

    @pytest.fixture
    def settings(self) -> MqttAuthSettings:
        return MqttAuthSettings()

    def test_a_service_account_is_a_service(self, mint_token, settings):
        """@verifies REQ-0014"""
        subject = _extract_subject_from_token(
            mint_token("svc-pipelines", scope="pipelines.runs.read"), settings
        )
        assert subject is not None
        assert subject.type is SubjectType.SERVICE
        assert subject.scopes == ["pipelines.runs.read"]

    def test_a_person_is_a_user_whatever_scopes_it_carries(self, mint_token, settings):
        """A browser token carries the scopes its client requested; it stays a user.

        Before REQ-0014 a person's token holding no group was judged as a service.

        @verifies REQ-0014
        """
        subject = _extract_subject_from_token(
            mint_token("u-2", scope="pipelines.admin", preferred_username="alice", email="a@x"),
            settings,
        )
        assert subject is not None
        assert subject.type is SubjectType.USER
        assert subject.scopes == ["pipelines.admin"]

    def test_a_service_account_holding_a_group_is_still_a_service(self, mint_token, settings):
        """"Has any group" no longer decides. @verifies REQ-0014"""
        subject = _extract_subject_from_token(
            mint_token("svc-pipelines", scope="pipelines.runs.read", groups=["/viewers"]),
            settings,
        )
        assert subject is not None
        assert subject.type is SubjectType.SERVICE
        assert subject.groups == []

    @pytest.mark.parametrize(
        "claims",
        [
            {"groups": ["/admins", "admins", "/pipelines.runs.read", "mqtt.admin"]},
            {"organization": {"example-rec": {"groups": ["/pipelines.runs.read", "/admins"]}}},
            {"realm_access": {"roles": ["platform-admin"]}},
        ],
    )
    def test_no_group_of_either_level_reaches_the_subject(self, mint_token, settings, claims):
        """@verifies REQ-0014"""
        subject = _extract_subject_from_token(mint_token("u-3", **claims), settings)
        assert subject is not None
        assert subject.type is SubjectType.USER
        assert subject.groups == []

    def test_neither_scope_nor_group_is_a_user_with_nothing(self, mint_token, settings):
        """Valid signature, zero authority."""
        subject = _extract_subject_from_token(mint_token("nobody"), settings)
        assert subject is not None
        assert subject.type is SubjectType.USER
        assert subject.scopes == []
        assert subject.groups == []

    def test_space_separated_scope_string_is_split(self, mint_token, settings):
        subject = _extract_subject_from_token(
            mint_token("svc-x", scope="a.read b.write c.admin"), settings
        )
        assert subject is not None
        assert subject.scopes == ["a.read", "b.write", "c.admin"]

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
        assert subject.type is SubjectType.SERVICE

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

    @pytest.mark.parametrize(
        "claims",
        [
            {"groups": ["/pipelines.runs.read"]},
            {"groups": ["/admins", "admins", "admin", "mqtt.admin"]},
            {"organization": {"example-rec": {"groups": ["/pipelines.runs.read", "/admins"]}}},
            {"realm_access": {"roles": ["platform-admin"]}},
            {"scope": "pipelines.runs.read pipelines.admin", "email": "a@x"},
        ],
    )
    @pytest.mark.parametrize("topic", [TOPIC, "celine/pipelines", "celine/pipelines/#"])
    def test_a_person_reaches_no_topic(self, client: TestClient, bearer, claims, topic):
        """No group (realm or organization), no role and no scope grants a user anything.

        @verifies REQ-0014
        """
        response = self._acl(client, bearer("u-1", **claims), topic=topic, acc=4)

        assert response.status_code == 403

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
# POST /superuser — there is none (REQ-0014)
# ---------------------------------------------------------------------------


class TestSuperuserEndpoint:
    def _superuser(self, client: TestClient, headers: dict[str, str]):
        return client.post("/superuser", headers=headers, json={"username": "any"})

    @pytest.mark.parametrize(
        ("sub", "claims"),
        [
            ("svc-admin", {"scope": "mqtt.admin"}),
            ("svc-pipelines", {"scope": "pipelines.admin"}),
            ("u-admin", {"groups": ["/admin"]}),
            ("u-admin", {"groups": ["/mqtt.admin"]}),
            ("u-admin", {"groups": ["/admins", "admins"]}),
            ("u-admin", {"organization": {"example-rec": {"groups": ["/admin", "/mqtt.admin"]}}}),
            ("u-admin", {"realm_access": {"roles": ["platform-admin"]}}),
            ("u-1", {"scope": "mqtt.admin", "groups": ["/mqtt.admin"]}),
        ],
    )
    def test_nobody_is_a_superuser(self, client: TestClient, bearer, sub, claims):
        """No scope, group or role — a platform admin included.

        @verifies REQ-0014
        """
        response = self._superuser(client, bearer(sub, **claims))

        assert response.status_code == 403
        assert response.json() == {"ok": False, "reason": "superuser disabled"}

    @pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer not.a.jwt"}])
    def test_no_token_and_a_bad_token_are_refused_too(self, client: TestClient, headers):
        """@verifies REQ-0014"""
        response = self._superuser(client, headers)

        assert response.status_code == 403
        assert response.json()["ok"] is False

    def test_the_superuser_scope_setting_is_gone(self):
        """Nothing left to configure. @verifies REQ-0014"""
        assert "mqtt_superuser_scope" not in MqttAuthSettings.model_fields


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
        monkeypatch.setenv("CELINE_ENV", "dev")  # see the `app` fixture

        from celine.mqtt_auth.main import create_app

        app = create_app()
        client = TestClient(app)
        headers = bearer("svc-pipelines", scope="pipelines.runs.read")
        for _ in range(3):
            assert self._acl(client, headers).status_code == 200

        assert app.state.engine.cache_stats["hits"] == 0
