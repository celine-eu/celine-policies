"""Tests for MQTT authorization endpoints."""

import pytest
from unittest.mock import MagicMock

from fastapi.testclient import TestClient


@pytest.fixture
def mock_jwt_validator():
    """Create a mock JWT validator."""
    mock = MagicMock()
    mock.validate.return_value = {
        "sub": "svc-pipelines",
        "scope": "pipeline.status.read pipeline.status.write",
        "client_id": "svc-pipelines",
    }
    return mock


@pytest.fixture
def mock_policy_api():
    """Create a mock PolicyAPI."""
    return MagicMock()


@pytest.fixture
def client(mock_jwt_validator, mock_policy_api):
    """Create test client with mocked dependencies."""
    from celine.policies.main import create_app
    from celine.policies.routes import deps

    app = create_app()

    async def override_get_jwt_validator():
        return mock_jwt_validator

    async def override_get_policy_api():
        return mock_policy_api

    app.dependency_overrides[deps.get_jwt_validator] = override_get_jwt_validator
    app.dependency_overrides[deps.get_policy_api] = override_get_policy_api

    return TestClient(app)


class TestMqttUserEndpoint:
    """Tests for POST /mqtt/user (authentication)."""

    def test_mqtt_user_valid_token(self, client, mock_jwt_validator):
        """Test successful MQTT authentication."""
        response = client.post(
            "/mqtt/user",
            headers={"Authorization": "Bearer valid.jwt.token"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        assert data["reason"] == "authenticated"

    def test_mqtt_user_missing_token(self, client):
        """Test MQTT auth without token."""
        response = client.post("/mqtt/user")

        assert response.status_code == 403
        data = response.json()
        assert data["ok"] is False
        assert "missing token" in data["reason"]

    def test_mqtt_user_invalid_token(self, client, mock_jwt_validator):
        """Test MQTT auth with invalid token."""
        from celine.policies.auth import JWTValidationError

        mock_jwt_validator.validate.side_effect = JWTValidationError("invalid")

        response = client.post(
            "/mqtt/user",
            headers={"Authorization": "Bearer invalid.token"},
        )

        assert response.status_code == 403
        data = response.json()
        assert data["ok"] is False
        assert "invalid credentials" in data["reason"]


class TestMqttAclEndpoint:
    """Tests for POST /mqtt/acl (authorization)."""

    def test_mqtt_acl_subscribe_allowed(self, client, mock_policy_api):
        """Test MQTT subscribe authorization."""
        from celine.policies.models import Decision

        mock_result = MagicMock()
        mock_result.decision = Decision(
            allowed=True,
            reason="service authorized via scope",
            policy="celine.mqtt",
        )
        mock_policy_api.evaluate.return_value = mock_result

        response = client.post(
            "/mqtt/acl",
            headers={"Authorization": "Bearer valid.jwt.token"},
            json={
                "topic": "celine/pipeline/status/job-123",
                "acc": 4,  # subscribe
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True

    def test_mqtt_acl_publish_allowed(self, client, mock_policy_api):
        """Test MQTT publish authorization."""
        from celine.policies.models import Decision

        mock_result = MagicMock()
        mock_result.decision = Decision(
            allowed=True,
            reason="service authorized via scope",
            policy="celine.mqtt",
        )
        mock_policy_api.evaluate.return_value = mock_result

        response = client.post(
            "/mqtt/acl",
            headers={"Authorization": "Bearer valid.jwt.token"},
            json={
                "topic": "celine/pipeline/status/job-123",
                "acc": 2,  # publish
            },
        )

        assert response.status_code == 200
        assert response.json()["ok"] is True

    def test_mqtt_acl_denied(self, client, mock_policy_api):
        """Test MQTT authorization denied."""
        from celine.policies.models import Decision

        mock_result = MagicMock()
        mock_result.decision = Decision(
            allowed=False,
            reason="missing required scope",
            policy="celine.mqtt",
        )
        mock_policy_api.evaluate.return_value = mock_result

        response = client.post(
            "/mqtt/acl",
            headers={"Authorization": "Bearer valid.jwt.token"},
            json={
                "topic": "celine/dt/simulation/sim-123",
                "acc": 2,  # publish
            },
        )

        assert response.status_code == 403
        data = response.json()
        assert data["ok"] is False
        assert "missing required scope" in data["reason"]

    def test_mqtt_acl_missing_token(self, client):
        """Test MQTT ACL without token."""
        response = client.post(
            "/mqtt/acl",
            json={"topic": "celine/dt/test", "acc": 1},
        )

        assert response.status_code == 403
        assert response.json()["ok"] is False

    def test_mqtt_acl_multiple_actions(self, client, mock_policy_api):
        """Test MQTT ACL with combined acc (read + publish)."""
        from celine.policies.models import Decision

        mock_result = MagicMock()
        mock_result.decision = Decision(
            allowed=True,
            reason="authorized",
            policy="celine.mqtt",
        )
        mock_policy_api.evaluate.return_value = mock_result

        response = client.post(
            "/mqtt/acl",
            headers={"Authorization": "Bearer valid.jwt.token"},
            json={
                "topic": "celine/pipeline/status/job-123",
                "acc": 3,  # read (1) + publish (2)
            },
        )

        assert response.status_code == 200
        # Should have called evaluate twice (once for each action)
        assert mock_policy_api.evaluate.call_count == 2


class TestMqttSuperuserEndpoint:
    """Tests for POST /mqtt/superuser."""

    def test_mqtt_superuser_with_admin_scope(self, client, mock_jwt_validator):
        """Test superuser check with mqtt.admin scope."""
        mock_jwt_validator.validate.return_value = {
            "sub": "svc-admin",
            "scope": "mqtt.admin dt.admin",
            "client_id": "svc-admin",
        }

        response = client.post(
            "/mqtt/superuser",
            headers={"Authorization": "Bearer admin.jwt.token"},
            json={"username": "svc-admin"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        assert data["reason"] == "superuser"

    def test_mqtt_superuser_without_admin_scope(self, client, mock_jwt_validator):
        """Test superuser check without mqtt.admin scope."""
        mock_jwt_validator.validate.return_value = {
            "sub": "svc-pipelines",
            "scope": "pipeline.status.read",
            "client_id": "svc-pipelines",
        }

        response = client.post(
            "/mqtt/superuser",
            headers={"Authorization": "Bearer normal.jwt.token"},
            json={"username": "svc-pipelines"},
        )

        assert response.status_code == 403
        data = response.json()
        assert data["ok"] is False
        assert "not superuser" in data["reason"]


class TestAccBitmaskConversion:
    """Tests for _acc_to_actions helper."""

    def test_acc_read_only(self):
        from celine.policies.routes.mqtt import _acc_to_actions

        assert _acc_to_actions(1) == ["read"]

    def test_acc_publish_only(self):
        from celine.policies.routes.mqtt import _acc_to_actions

        assert _acc_to_actions(2) == ["publish"]

    def test_acc_subscribe_only(self):
        from celine.policies.routes.mqtt import _acc_to_actions

        assert _acc_to_actions(4) == ["subscribe"]

    def test_acc_read_publish(self):
        from celine.policies.routes.mqtt import _acc_to_actions

        actions = _acc_to_actions(3)
        assert "read" in actions
        assert "publish" in actions

    def test_acc_all(self):
        from celine.policies.routes.mqtt import _acc_to_actions

        actions = _acc_to_actions(7)
        assert "read" in actions
        assert "publish" in actions
        assert "subscribe" in actions

    def test_acc_zero(self):
        from celine.policies.routes.mqtt import _acc_to_actions

        assert _acc_to_actions(0) == ["unknown"]
