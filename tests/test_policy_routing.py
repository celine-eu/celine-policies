"""Tests for policy routing logic."""

import pytest
from pathlib import Path


@pytest.fixture
def policies_dir(tmp_path):
    """Create policies with specialized and generic packages."""
    policies = tmp_path / "policies" / "celine"
    policies.mkdir(parents=True)

    # Shared scopes
    (policies / "scopes.rego").write_text(
        """
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

is_service if input.subject.type == "service"
is_anonymous if input.subject == null
"""
    )

    # Generic fallback
    (policies / "authz.rego").write_text(
        """
package celine.authz

import rego.v1
import data.celine.scopes

default allow := false
default reason := "unauthorized"

allow if {
    scopes.is_service
    scopes.has_scope(required_scope)
}

reason := "authorized via generic policy" if {
    scopes.is_service
    scopes.has_scope(required_scope)
}

required_scope := concat(".", [input.resource.type, input.resource.attributes.resource_type, input.action.name]) if {
    input.resource.attributes.resource_type
}

required_scope := concat(".", [input.resource.type, input.action.name]) if {
    not input.resource.attributes.resource_type
}

reason := "missing required scope" if {
    not allow
    scopes.is_service
}
"""
    )

    # Specialized dataset policy
    (policies / "dataset.rego").write_text(
        """
package celine.dataset

import rego.v1
import data.celine.scopes

default allow := false
default reason := "unauthorized"

is_open if input.resource.attributes.access_level == "open"
is_restricted if input.resource.attributes.access_level == "restricted"

# Open datasets: no scope needed for read
allow if {
    scopes.is_service
    is_open
    input.action.name in ["query", "read"]
}

reason := "open dataset - public access" if {
    scopes.is_service
    is_open
    input.action.name in ["query", "read"]
}

# Restricted: admin only
allow if {
    scopes.is_service
    is_restricted
    scopes.has_scope("dataset.admin")
}

reason := "restricted dataset - admin authorized" if {
    scopes.is_service
    is_restricted
    scopes.has_scope("dataset.admin")
}

# Internal (default): check scope
allow if {
    scopes.is_service
    not is_open
    not is_restricted
    scopes.has_scope(required_scope)
}

reason := "dataset access authorized" if {
    scopes.is_service
    not is_open
    not is_restricted
    scopes.has_scope(required_scope)
}

required_scope := "dataset.query" if input.action.name == "query"
required_scope := "dataset.read" if input.action.name == "read"
required_scope := "dataset.write" if input.action.name == "write"
required_scope := "dataset.admin" if input.action.name in ["create", "delete", "admin"]

reason := "restricted dataset requires admin scope" if {
    not allow
    scopes.is_service
    is_restricted
}

reason := "missing dataset scope" if {
    not allow
    scopes.is_service
    not is_restricted
}
"""
    )

    return tmp_path / "policies"


@pytest.fixture
def engine(policies_dir):
    """Create engine with test policies."""
    from celine.policies.engine import PolicyEngine

    engine = PolicyEngine(policies_dir=policies_dir, data_dir=None)
    engine.load()
    return engine


class TestPackageDetection:
    """Tests for has_package routing."""

    def test_has_specialized_package(self, engine):
        """Dataset package should exist."""
        assert engine.has_package("celine.dataset")

    def test_has_generic_package(self, engine):
        """Generic authz package should exist."""
        assert engine.has_package("celine.authz")

    def test_missing_package(self, engine):
        """Non-existent package should return False."""
        assert not engine.has_package("celine.dt")
        assert not engine.has_package("celine.pipeline")

    def test_get_packages(self, engine):
        """Should list all loaded packages."""
        packages = engine.get_packages()
        assert "celine.scopes" in packages
        assert "celine.authz" in packages
        assert "celine.dataset" in packages


class TestPolicyRouting:
    """Tests for resolve_policy_package."""

    def test_route_to_specialized(self, engine):
        """Dataset should route to specialized policy."""
        from celine.policies.routes.authorize import resolve_policy_package

        assert resolve_policy_package(engine, "dataset") == "celine.dataset"

    def test_route_to_fallback(self, engine):
        """Unknown types should route to generic."""
        from celine.policies.routes.authorize import resolve_policy_package

        assert resolve_policy_package(engine, "dt") == "celine.authz"
        assert resolve_policy_package(engine, "pipeline") == "celine.authz"
        assert resolve_policy_package(engine, "unknown") == "celine.authz"


class TestSpecializedDatasetPolicy:
    """Tests for dataset-specific logic via routing."""

    def test_open_dataset_no_scope_needed(self, engine):
        """Open dataset should allow query without scope."""
        from celine.policies.models import (
            Action,
            PolicyInput,
            Resource,
            ResourceType,
            Subject,
            SubjectType,
        )

        policy_input = PolicyInput(
            subject=Subject(
                id="svc-any", type=SubjectType.SERVICE, groups=[], scopes=[], claims={}
            ),
            resource=Resource(
                type=ResourceType.DATASET,
                id="ds-public",
                attributes={"access_level": "open"},
            ),
            action=Action(name="query", context={}),
            environment={},
        )

        decision = engine.evaluate_decision("celine.dataset", policy_input)
        assert decision.allowed is True
        assert "open dataset" in decision.reason

    def test_restricted_dataset_needs_admin(self, engine):
        """Restricted dataset should require admin scope."""
        from celine.policies.models import (
            Action,
            PolicyInput,
            Resource,
            ResourceType,
            Subject,
            SubjectType,
        )

        # Without admin scope
        policy_input = PolicyInput(
            subject=Subject(
                id="svc-any",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["dataset.query"],
                claims={},
            ),
            resource=Resource(
                type=ResourceType.DATASET,
                id="ds-secret",
                attributes={"access_level": "restricted"},
            ),
            action=Action(name="query", context={}),
            environment={},
        )

        decision = engine.evaluate_decision("celine.dataset", policy_input)
        assert decision.allowed is False
        assert "restricted" in decision.reason

        # With admin scope
        assert policy_input.subject is not None

        policy_input.subject.scopes = ["dataset.admin"]
        decision = engine.evaluate_decision("celine.dataset", policy_input)
        assert decision.allowed is True

    def test_internal_dataset_needs_scope(self, engine):
        """Internal dataset should require matching scope."""
        from celine.policies.models import (
            Action,
            PolicyInput,
            Resource,
            ResourceType,
            Subject,
            SubjectType,
        )

        policy_input = PolicyInput(
            subject=Subject(
                id="svc-dt",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["dataset.query"],
                claims={},
            ),
            resource=Resource(
                type=ResourceType.DATASET,
                id="ds-123",
                attributes={},
            ),
            action=Action(name="query", context={}),
            environment={},
        )

        decision = engine.evaluate_decision("celine.dataset", policy_input)
        assert decision.allowed is True


class TestGenericFallbackPolicy:
    """Tests for generic policy via routing."""

    def test_dt_uses_fallback(self, engine):
        """DT should use generic policy with scope derivation."""
        from celine.policies.models import (
            Action,
            PolicyInput,
            Resource,
            ResourceType,
            Subject,
            SubjectType,
        )

        policy_input = PolicyInput(
            subject=Subject(
                id="svc-dt",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["dt.simulation.read"],
                claims={},
            ),
            resource=Resource(
                type=ResourceType.DT,
                id="sim-123",
                attributes={"resource_type": "simulation"},
            ),
            action=Action(name="read", context={}),
            environment={},
        )

        decision = engine.evaluate_decision("celine.authz", policy_input)
        assert decision.allowed is True
        assert "generic policy" in decision.reason

    def test_dt_admin_scope_works(self, engine):
        """Admin scope should work in fallback."""
        from celine.policies.models import (
            Action,
            PolicyInput,
            Resource,
            ResourceType,
            Subject,
            SubjectType,
        )

        policy_input = PolicyInput(
            subject=Subject(
                id="svc-dt",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["dt.admin"],
                claims={},
            ),
            resource=Resource(
                type=ResourceType.DT,
                id="sim-123",
                attributes={"resource_type": "simulation"},
            ),
            action=Action(name="write", context={}),
            environment={},
        )

        decision = engine.evaluate_decision("celine.authz", policy_input)
        assert decision.allowed is True

    def test_cross_service_denied(self, engine):
        """Cross-service access should be denied."""
        from celine.policies.models import (
            Action,
            PolicyInput,
            Resource,
            ResourceType,
            Subject,
            SubjectType,
        )

        policy_input = PolicyInput(
            subject=Subject(
                id="svc-pipelines",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["pipeline.status.read"],
                claims={},
            ),
            resource=Resource(
                type=ResourceType.DT,
                id="sim-123",
                attributes={"resource_type": "simulation"},
            ),
            action=Action(name="read", context={}),
            environment={},
        )

        decision = engine.evaluate_decision("celine.authz", policy_input)
        assert decision.allowed is False
