"""The MQTT auth backend's posture: what it refuses outside dev (NIS2 R24).

Only `CELINE_ENV=dev` relaxes (`celine.sdk.posture`). Hardened, the service must
name the audience its tokens are for — without one any client's token is an MQTT
credential — and must not run on the SDK's local Keycloak defaults. Either way a
configured audience is enforced on every token. There is no CORS in any environment, and
the API docs are served only in dev or when opted in.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest
from celine.sdk.posture import InsecureConfiguration
from fastapi.testclient import TestClient

from celine.mqtt_auth.config import MqttAuthSettings, check_posture

POLICIES_DIR = str(Path(__file__).resolve().parents[1] / "policies")
ISSUER = "http://keycloak.celine.localhost/realms/celine"
JWKS = f"{ISSUER}/protocol/openid-connect/certs"
AUDIENCE = "mqtt-audience-under-test"


@pytest.fixture
def hardened_env(monkeypatch: pytest.MonkeyPatch):
    """A fully configured hardened deployment; each test removes one piece."""
    monkeypatch.setenv("CELINE_ENV", "prod")
    monkeypatch.setenv("CELINE_POLICIES_DIR", POLICIES_DIR)
    monkeypatch.setenv("CELINE_OIDC_BASE_URL", ISSUER)
    monkeypatch.setenv("CELINE_OIDC_JWKS_URI", JWKS)
    monkeypatch.setenv("CELINE_OIDC_AUDIENCE", AUDIENCE)
    return monkeypatch


def _create_app():
    from celine.mqtt_auth.main import create_app

    return create_app()


class TestAudienceSetting:
    def test_the_audience_is_read_from_the_environment(self, monkeypatch):
        """It used to be pinned to None in code, whatever the environment said.

        @verifies REQ-0009
        """
        monkeypatch.setenv("CELINE_OIDC_AUDIENCE", AUDIENCE)

        assert MqttAuthSettings().oidc.audience == AUDIENCE

    def test_unset_it_is_none(self):
        """@verifies REQ-0009"""
        assert MqttAuthSettings().oidc.audience is None


class TestHardenedStartup:
    def test_a_complete_configuration_starts(self, hardened_env):
        """@verifies REQ-0009"""
        app = _create_app()

        assert TestClient(app).get("/health").status_code == 200

    @pytest.mark.parametrize("env", [None, "prod", "staging", "test", "local", "ci", "development"])
    def test_no_audience_refuses_to_start_outside_dev(self, hardened_env, env):
        """@verifies REQ-0009"""
        hardened_env.delenv("CELINE_OIDC_AUDIENCE")
        if env is None:
            hardened_env.delenv("CELINE_ENV")
        else:
            hardened_env.setenv("CELINE_ENV", env)

        with pytest.raises(InsecureConfiguration, match="CELINE_OIDC_AUDIENCE"):
            _create_app()

    @pytest.mark.parametrize("name", ["CELINE_OIDC_BASE_URL", "CELINE_OIDC_JWKS_URI"])
    def test_the_sdk_oidc_defaults_refuse_to_start_outside_dev(self, hardened_env, name):
        """@verifies REQ-0009"""
        hardened_env.delenv(name)

        with pytest.raises(InsecureConfiguration, match=name):
            _create_app()

    def test_every_violation_is_listed_at_once(self, monkeypatch):
        """@verifies REQ-0009"""
        with pytest.raises(InsecureConfiguration) as err:
            check_posture(MqttAuthSettings(), env="prod")

        for name in ("CELINE_OIDC_AUDIENCE", "CELINE_OIDC_BASE_URL", "CELINE_OIDC_JWKS_URI"):
            assert name in str(err.value)

    def test_the_environment_variable_is_the_second_signal(self, hardened_env):
        """`ENVIRONMENT=dev` relaxes like `CELINE_ENV=dev`; `CELINE_ENV` wins.

        @verifies REQ-0009
        """
        hardened_env.delenv("CELINE_OIDC_AUDIENCE")
        hardened_env.setenv("ENVIRONMENT", "dev")

        with pytest.raises(InsecureConfiguration):
            _create_app()

        hardened_env.delenv("CELINE_ENV")
        _create_app()


class TestDevStartup:
    def test_dev_starts_without_an_audience_and_warns(self, monkeypatch, caplog):
        """@verifies REQ-0009"""
        monkeypatch.setenv("CELINE_ENV", "dev")
        monkeypatch.setenv("CELINE_POLICIES_DIR", POLICIES_DIR)

        app = _create_app()

        assert TestClient(app).get("/health").status_code == 200
        assert "CELINE_OIDC_AUDIENCE" in caplog.text


class TestAudienceEnforcement:
    def test_a_token_for_another_audience_is_rejected(self, hardened_env, bearer):
        """@verifies REQ-0009"""
        client = TestClient(_create_app())

        response = client.post(
            "/user", headers=bearer("svc-other", scope="x", aud="svc-another-service")
        )

        assert response.status_code == 403

    def test_a_token_without_an_audience_is_rejected(self, hardened_env, bearer):
        """@verifies REQ-0009"""
        client = TestClient(_create_app())

        assert client.post("/user", headers=bearer("svc-other")).status_code == 403

    def test_a_token_carrying_the_audience_is_accepted(self, hardened_env, bearer):
        """Keycloak issues `aud` as a list when several mappers apply.

        @verifies REQ-0009
        """
        client = TestClient(_create_app())

        response = client.post(
            "/user", headers=bearer("svc-pipelines", aud=["svc-flexibility", AUDIENCE])
        )

        assert response.status_code == 200

    def test_the_audience_is_enforced_in_dev_too_once_set(self, monkeypatch, bearer):
        """Optional in dev means it may be left unset, not that it is ignored.

        @verifies REQ-0009
        """
        monkeypatch.setenv("CELINE_ENV", "dev")
        monkeypatch.setenv("CELINE_POLICIES_DIR", POLICIES_DIR)
        monkeypatch.setenv("CELINE_OIDC_AUDIENCE", AUDIENCE)
        client = TestClient(_create_app())

        assert client.post("/user", headers=bearer("svc-x", aud="svc-y")).status_code == 403
        assert client.post("/user", headers=bearer("svc-x", aud=AUDIENCE)).status_code == 200


class TestCors:
    PREFLIGHT: ClassVar[dict[str, str]] = {
        "Origin": "http://other.example.org",
        "Access-Control-Request-Method": "POST",
    }

    def _assert_no_cors(self, client: TestClient) -> None:
        preflight = client.options("/user", headers=self.PREFLIGHT)
        health = client.get("/health", headers={"Origin": "http://other.example.org"})

        assert "access-control-allow-origin" not in preflight.headers
        assert "access-control-allow-origin" not in health.headers
        assert "access-control-allow-credentials" not in health.headers

    def test_dev_has_no_cors(self, monkeypatch):
        """No browser calls the broker's auth backend, in dev either.

        @verifies REQ-0010
        """
        monkeypatch.setenv("CELINE_ENV", "dev")
        monkeypatch.setenv("CELINE_POLICIES_DIR", POLICIES_DIR)

        self._assert_no_cors(TestClient(_create_app()))

    def test_hardened_has_no_cors(self, hardened_env):
        """@verifies REQ-0010"""
        self._assert_no_cors(TestClient(_create_app()))


class TestApiDocs:
    PATHS: ClassVar[tuple[str, ...]] = ("/docs", "/redoc", "/openapi.json")

    def test_hardened_serves_no_docs(self, hardened_env):
        """@verifies REQ-0018"""
        client = TestClient(_create_app())

        for path in self.PATHS:
            assert client.get(path).status_code == 404, path

    def test_hardened_serves_them_when_opted_in(self, hardened_env):
        """@verifies REQ-0018"""
        hardened_env.setenv("CELINE_PUBLIC_DOCS", "true")
        client = TestClient(_create_app())

        for path in self.PATHS:
            assert client.get(path).status_code == 200, path

    def test_dev_serves_them(self, monkeypatch):
        """@verifies REQ-0018"""
        monkeypatch.setenv("CELINE_ENV", "dev")
        monkeypatch.setenv("CELINE_POLICIES_DIR", POLICIES_DIR)
        client = TestClient(_create_app())

        for path in self.PATHS:
            assert client.get(path).status_code == 200, path
