"""Tests for the unified /authorize endpoint."""

import pytest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient


# Mock the dependencies before importing the app
@pytest.fixture
def mock_policy_api():
    """Create a mock PolicyAPI."""
    mock = MagicMock()
    return mock


@pytest.fixture
def mock_subject():
    """Create a mock Subject."""
    from celine.policies.models import Subject, SubjectType

    return Subject(
        id="svc-digital-twin",
        type=SubjectType.SERVICE,
        groups=[],
        scopes=["dt.simulation.read", "dt.values.read"],
        claims={},
    )


@pytest.fixture
def client(mock_policy_api, mock_subject):
    from celine.policies.main import create_app
    from celine.policies.routes import deps
    from fastapi.testclient import TestClient
    from unittest.mock import MagicMock

    app = create_app()

    async def override_get_policy_api():
        return mock_policy_api

    async def override_get_subject(authorization=None, jwt_validator=None):
        return mock_subject

    # NEW: override engine used for routing
    fake_engine = MagicMock()
    fake_engine.has_package.return_value = (
        False  # forces fallback to celine.authz for dt/pipeline
    )

    async def override_get_policy_engine():
        return fake_engine

    app.dependency_overrides[deps.get_policy_api] = override_get_policy_api
    app.dependency_overrides[deps.get_subject] = override_get_subject
    app.dependency_overrides[deps.get_policy_engine] = override_get_policy_engine

    return TestClient(app)


class TestAuthorizeEndpoint:
    """Tests for POST /authorize."""

    def test_authorize_allowed(self, client, mock_policy_api):
        """Test successful authorization."""
        from celine.policies.models import Decision

        mock_result = MagicMock()
        mock_result.decision = Decision(
            allowed=True,
            reason="authorized",
            policy="celine.authz",
        )
        mock_policy_api.evaluate.return_value = mock_result

        response = client.post(
            "/authorize",
            json={
                "resource": {
                    "type": "dt",
                    "id": "sim-123",
                    "attributes": {"resource_type": "simulation"},
                },
                "action": {"name": "read"},
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["allowed"] is True
        assert data["reason"] == "authorized"
        assert "request_id" in data

    def test_authorize_denied(self, client, mock_policy_api):
        """Test denied authorization."""
        from celine.policies.models import Decision

        mock_result = MagicMock()
        mock_result.decision = Decision(
            allowed=False,
            reason="missing required scope",
            policy="celine.authz",
        )
        mock_policy_api.evaluate.return_value = mock_result

        response = client.post(
            "/authorize",
            json={
                "resource": {
                    "type": "dt",
                    "id": "sim-123",
                    "attributes": {"resource_type": "simulation"},
                },
                "action": {"name": "write"},
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["allowed"] is False
        assert data["reason"] == "missing required scope"

    def test_authorize_with_custom_request_id(self, client, mock_policy_api):
        """Test that custom request ID is used."""
        from celine.policies.models import Decision

        mock_result = MagicMock()
        mock_result.decision = Decision(
            allowed=True,
            reason="authorized",
            policy="celine.authz",
        )
        mock_policy_api.evaluate.return_value = mock_result

        response = client.post(
            "/authorize",
            headers={"X-Request-ID": "custom-123"},
            json={
                "resource": {"type": "dt", "id": "sim-1", "attributes": {}},
                "action": {"name": "read"},
            },
        )

        assert response.status_code == 200
        assert response.json()["request_id"] == "custom-123"

    def test_authorize_policy_input_structure(self, client, mock_policy_api):
        """Test that PolicyInput is correctly structured."""
        from celine.policies.models import Decision

        mock_result = MagicMock()
        mock_result.decision = Decision(
            allowed=True, reason="ok", policy="celine.authz"
        )
        mock_policy_api.evaluate.return_value = mock_result

        client.post(
            "/authorize",
            json={
                "resource": {
                    "type": "pipeline",
                    "id": "job-456",
                    "attributes": {"resource_type": "status"},
                },
                "action": {"name": "write", "context": {"priority": "high"}},
                "context": {"source": "test"},
            },
        )

        # Verify evaluate was called with correct arguments
        call_args = mock_policy_api.evaluate.call_args
        assert call_args is not None

        kwargs = call_args.kwargs
        assert kwargs["policy_package"] == "celine.authz"

        policy_input = kwargs["policy_input"]
        assert policy_input.resource.type.value == "pipeline"
        assert policy_input.resource.id == "job-456"
        assert policy_input.resource.attributes["resource_type"] == "status"
        assert policy_input.action.name == "write"


class TestAuthorizeScenarios:
    """Integration-style tests for common authorization scenarios."""

    def test_dt_simulation_read(self, client, mock_policy_api):
        """Scenario: Digital twin service reads simulation."""
        from celine.policies.models import Decision

        mock_result = MagicMock()
        mock_result.decision = Decision(
            allowed=True, reason="authorized", policy="celine.authz"
        )
        mock_policy_api.evaluate.return_value = mock_result

        response = client.post(
            "/authorize",
            json={
                "resource": {
                    "type": "dt",
                    "id": "sim-123",
                    "attributes": {"resource_type": "simulation"},
                },
                "action": {"name": "read"},
            },
        )

        assert response.status_code == 200
        assert response.json()["allowed"] is True

    def test_pipeline_status_write(self, client, mock_policy_api):
        """Scenario: Pipeline service updates status."""
        from celine.policies.models import Decision

        mock_result = MagicMock()
        mock_result.decision = Decision(
            allowed=True, reason="authorized", policy="celine.authz"
        )
        mock_policy_api.evaluate.return_value = mock_result

        response = client.post(
            "/authorize",
            json={
                "resource": {
                    "type": "pipeline",
                    "id": "job-789",
                    "attributes": {"resource_type": "status"},
                },
                "action": {"name": "write"},
            },
        )

        assert response.status_code == 200

    def test_dataset_query_no_resource_type(self, client, mock_policy_api):
        """Scenario: Dataset query without resource_type (fallback)."""
        from celine.policies.models import Decision

        mock_result = MagicMock()
        mock_result.decision = Decision(
            allowed=True, reason="authorized", policy="celine.authz"
        )
        mock_policy_api.evaluate.return_value = mock_result

        response = client.post(
            "/authorize",
            json={
                "resource": {
                    "type": "dataset",
                    "id": "ds-energy",
                    "attributes": {},
                },
                "action": {"name": "query"},
            },
        )

        assert response.status_code == 200
