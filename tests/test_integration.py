"""Integration tests for authorization with real Rego policies.

These tests load the actual Rego policies and verify end-to-end behavior.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from fastapi.testclient import TestClient


@pytest.fixture
def policies_dir(tmp_path):
    """Create a temporary policies directory with test policies."""
    policies = tmp_path / "policies" / "celine"
    policies.mkdir(parents=True)

    # Write scopes.rego
    (policies / "scopes.rego").write_text('''
package celine.scopes

import rego.v1

has_scope(required) if {
    some have in input.subject.scopes
    scope_matches(have, required)
}

scope_matches(have, want) if have == want

scope_matches(have, want) if {
    endswith(have, ".admin")
    service := trim_suffix(have, ".admin")
    startswith(want, concat("", [service, "."]))
}

scope_matches(have, want) if {
    endswith(have, ".*")
    prefix := trim_suffix(have, "*")
    startswith(want, prefix)
}

is_service if input.subject.type == "service"
is_anonymous if input.subject == null
''')

    # Write authz.rego
    (policies / "authz.rego").write_text('''
package celine.authz

import rego.v1
import data.celine.scopes

default allow := false
default reason := "unauthorized"

allow if {
    scopes.is_service
    required := required_scope
    scopes.has_scope(required)
}

reason := "authorized" if {
    scopes.is_service
    required := required_scope
    scopes.has_scope(required)
}

required_scope := scope if {
    rt := input.resource.attributes.resource_type
    rt != null
    rt != ""
    scope := concat(".", [input.resource.type, rt, input.action.name])
}

required_scope := scope if {
    not input.resource.attributes.resource_type
    scope := concat(".", [input.resource.type, input.action.name])
}

reason := "anonymous access denied" if {
    not allow
    scopes.is_anonymous
}

reason := "missing required scope" if {
    not allow
    scopes.is_service
}
''')

    # Write mqtt.rego
    (policies / "mqtt.rego").write_text('''
package celine.mqtt

import rego.v1
import data.celine.scopes

default allow := false
default reason := "unauthorized"

mqtt_action_map := {"subscribe": "read", "read": "read", "publish": "write"}

parse_topic(topic) := result if {
    parts := split(topic, "/")
    count(parts) >= 3
    parts[0] == "celine"
    result := {"service": parts[1], "resource": parts[2]}
}

required_scope(topic, mqtt_action) := scope if {
    parsed := parse_topic(topic)
    scope_action := mqtt_action_map[mqtt_action]
    scope := concat(".", [parsed.service, parsed.resource, scope_action])
}

allow if {
    scopes.is_service
    scope := required_scope(input.resource.id, input.action.name)
    scopes.has_scope(scope)
}

reason := "service authorized via scope" if {
    scopes.is_service
    scope := required_scope(input.resource.id, input.action.name)
    scopes.has_scope(scope)
}

reason := "missing required scope" if {
    not allow
    scopes.is_service
}
''')

    return tmp_path / "policies"


@pytest.fixture
def real_policy_engine(policies_dir):
    """Create a real PolicyEngine with test policies."""
    from celine.policies.engine.engine import PolicyEngine

    engine = PolicyEngine(policies_dir=policies_dir, data_dir=None)
    engine.load()
    return engine


@pytest.fixture
def real_policy_api(real_policy_engine):
    """Create a real PolicyAPI with the test engine."""
    from celine.policies.api import PolicyAPI

    return PolicyAPI(engine=real_policy_engine)


@pytest.fixture
def integration_client(real_policy_api):
    """Create test client with real policy engine."""
    from celine.policies.main import create_app
    from celine.policies.routes import deps
    from celine.policies.models import Subject, SubjectType

    app = create_app()

    # Store the subject to be used
    current_subject = None

    async def override_get_policy_api():
        return real_policy_api

    async def override_get_subject(authorization=None, jwt_validator=None):
        return current_subject

    app.dependency_overrides[deps.get_policy_api] = override_get_policy_api
    app.dependency_overrides[deps.get_subject] = override_get_subject

    client = TestClient(app)
    client._current_subject = None

    def set_subject(subject):
        nonlocal current_subject
        current_subject = subject

    client.set_subject = set_subject
    return client


class TestAuthzIntegration:
    """Integration tests for /authorize with real policies."""

    def test_dt_simulation_read_allowed(self, integration_client):
        """Test: service with dt.simulation.read can read simulations."""
        from celine.policies.models import Subject, SubjectType

        integration_client.set_subject(
            Subject(
                id="svc-digital-twin",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["dt.simulation.read"],
                claims={},
            )
        )

        response = integration_client.post(
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

    def test_dt_simulation_write_denied_with_read_scope(self, integration_client):
        """Test: service with dt.simulation.read cannot write simulations."""
        from celine.policies.models import Subject, SubjectType

        integration_client.set_subject(
            Subject(
                id="svc-digital-twin",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["dt.simulation.read"],
                claims={},
            )
        )

        response = integration_client.post(
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
        assert "missing required scope" in data["reason"]

    def test_admin_scope_allows_all(self, integration_client):
        """Test: dt.admin scope allows all dt.* operations."""
        from celine.policies.models import Subject, SubjectType

        integration_client.set_subject(
            Subject(
                id="svc-admin",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["dt.admin"],
                claims={},
            )
        )

        # Should allow simulation read
        response = integration_client.post(
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
        assert response.json()["allowed"] is True

        # Should allow values write
        response = integration_client.post(
            "/authorize",
            json={
                "resource": {
                    "type": "dt",
                    "id": "twin-456",
                    "attributes": {"resource_type": "values"},
                },
                "action": {"name": "write"},
            },
        )
        assert response.json()["allowed"] is True

        # Should allow app run
        response = integration_client.post(
            "/authorize",
            json={
                "resource": {
                    "type": "dt",
                    "id": "app-789",
                    "attributes": {"resource_type": "app"},
                },
                "action": {"name": "run"},
            },
        )
        assert response.json()["allowed"] is True

    def test_cross_service_denied(self, integration_client):
        """Test: pipeline scope cannot access dt resources."""
        from celine.policies.models import Subject, SubjectType

        integration_client.set_subject(
            Subject(
                id="svc-pipelines",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["pipeline.status.read", "pipeline.status.write"],
                claims={},
            )
        )

        response = integration_client.post(
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
        assert response.json()["allowed"] is False

    def test_anonymous_denied(self, integration_client):
        """Test: anonymous subject is denied."""
        integration_client.set_subject(None)

        response = integration_client.post(
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
        assert data["allowed"] is False
        assert "anonymous" in data["reason"]

    def test_dataset_query_fallback(self, integration_client):
        """Test: dataset.query works without resource_type."""
        from celine.policies.models import Subject, SubjectType

        integration_client.set_subject(
            Subject(
                id="svc-dataset",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["dataset.query"],
                claims={},
            )
        )

        response = integration_client.post(
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
        assert response.json()["allowed"] is True


class TestMqttIntegration:
    """Integration tests for MQTT with real policies."""

    def test_mqtt_topic_subscribe_allowed(self, real_policy_api):
        """Test: MQTT subscribe derives correct scope."""
        from celine.policies.models import (
            Action,
            PolicyInput,
            Resource,
            ResourceType,
            Subject,
            SubjectType,
        )

        subject = Subject(
            id="svc-pipelines",
            type=SubjectType.SERVICE,
            groups=[],
            scopes=["pipeline.status.read"],
            claims={},
        )

        policy_input = PolicyInput(
            subject=subject,
            resource=Resource(
                type=ResourceType.TOPIC,
                id="celine/pipeline/status/job-123",
                attributes={},
            ),
            action=Action(name="subscribe", context={}),
            environment={},
        )

        result = real_policy_api.evaluate(
            request_id="test-1",
            policy_package="celine.mqtt",
            policy_input=policy_input,
        )

        assert result.decision.allowed is True

    def test_mqtt_topic_publish_allowed(self, real_policy_api):
        """Test: MQTT publish derives write scope."""
        from celine.policies.models import (
            Action,
            PolicyInput,
            Resource,
            ResourceType,
            Subject,
            SubjectType,
        )

        subject = Subject(
            id="svc-pipelines",
            type=SubjectType.SERVICE,
            groups=[],
            scopes=["pipeline.status.write"],
            claims={},
        )

        policy_input = PolicyInput(
            subject=subject,
            resource=Resource(
                type=ResourceType.TOPIC,
                id="celine/pipeline/status/job-123",
                attributes={},
            ),
            action=Action(name="publish", context={}),
            environment={},
        )

        result = real_policy_api.evaluate(
            request_id="test-2",
            policy_package="celine.mqtt",
            policy_input=policy_input,
        )

        assert result.decision.allowed is True

    def test_mqtt_cross_service_denied(self, real_policy_api):
        """Test: pipeline scope cannot publish to dt topics."""
        from celine.policies.models import (
            Action,
            PolicyInput,
            Resource,
            ResourceType,
            Subject,
            SubjectType,
        )

        subject = Subject(
            id="svc-pipelines",
            type=SubjectType.SERVICE,
            groups=[],
            scopes=["pipeline.status.write"],
            claims={},
        )

        policy_input = PolicyInput(
            subject=subject,
            resource=Resource(
                type=ResourceType.TOPIC,
                id="celine/dt/simulation/sim-123",
                attributes={},
            ),
            action=Action(name="publish", context={}),
            environment={},
        )

        result = real_policy_api.evaluate(
            request_id="test-3",
            policy_package="celine.mqtt",
            policy_input=policy_input,
        )

        assert result.decision.allowed is False
