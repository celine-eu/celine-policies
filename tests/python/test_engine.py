"""Tests for the policy engine."""

import pytest
from pathlib import Path

from celine_policies.engine import PolicyEngine, PolicyEngineError, DecisionCache
from celine_policies.models import (
    Subject,
    SubjectType,
    Resource,
    ResourceType,
    Action,
    PolicyInput,
)


class TestPolicyEngine:
    """Tests for PolicyEngine."""

    @pytest.fixture
    def engine(self, policies_dir, data_dir):
        """Create a policy engine with test policies."""
        engine = PolicyEngine(policies_dir, data_dir)
        engine.load()
        return engine

    def test_engine_loads_policies(self, engine):
        """Test that policies are loaded."""
        assert engine.is_loaded
        assert engine.policy_count > 0

    def test_evaluate_open_dataset_anonymous(self, engine):
        """Test anonymous access to open dataset."""
        policy_input = PolicyInput(
            subject=None,
            resource=Resource(
                type=ResourceType.DATASET,
                id="ds-public",
                attributes={"access_level": "open"},
            ),
            action=Action(name="read", context={}),
        )
        
        decision = engine.evaluate_decision("celine.dataset.access", policy_input)
        
        assert decision.allowed is True

    def test_evaluate_internal_dataset_viewer(self, engine):
        """Test viewer access to internal dataset."""
        policy_input = PolicyInput(
            subject=Subject(
                id="user-1",
                type=SubjectType.USER,
                groups=["viewers"],
                scopes=[],
                claims={},
            ),
            resource=Resource(
                type=ResourceType.DATASET,
                id="ds-internal",
                attributes={"access_level": "internal"},
            ),
            action=Action(name="read", context={}),
        )
        
        decision = engine.evaluate_decision("celine.dataset.access", policy_input)
        
        assert decision.allowed is True

    def test_evaluate_internal_dataset_anonymous_denied(self, engine):
        """Test anonymous access to internal dataset is denied."""
        policy_input = PolicyInput(
            subject=None,
            resource=Resource(
                type=ResourceType.DATASET,
                id="ds-internal",
                attributes={"access_level": "internal"},
            ),
            action=Action(name="read", context={}),
        )
        
        decision = engine.evaluate_decision("celine.dataset.access", policy_input)
        
        assert decision.allowed is False

    def test_evaluate_restricted_dataset_admin_allowed(self, engine):
        """Test admin access to restricted dataset."""
        policy_input = PolicyInput(
            subject=Subject(
                id="admin-1",
                type=SubjectType.USER,
                groups=["admins"],
                scopes=[],
                claims={},
            ),
            resource=Resource(
                type=ResourceType.DATASET,
                id="ds-restricted",
                attributes={"access_level": "restricted"},
            ),
            action=Action(name="read", context={}),
        )
        
        decision = engine.evaluate_decision("celine.dataset.access", policy_input)
        
        assert decision.allowed is True

    def test_evaluate_restricted_dataset_viewer_denied(self, engine):
        """Test viewer access to restricted dataset is denied."""
        policy_input = PolicyInput(
            subject=Subject(
                id="user-1",
                type=SubjectType.USER,
                groups=["viewers"],
                scopes=[],
                claims={},
            ),
            resource=Resource(
                type=ResourceType.DATASET,
                id="ds-restricted",
                attributes={"access_level": "restricted"},
            ),
            action=Action(name="read", context={}),
        )
        
        decision = engine.evaluate_decision("celine.dataset.access", policy_input)
        
        assert decision.allowed is False

    def test_evaluate_service_with_query_scope(self, engine):
        """Test service with dataset.query scope."""
        policy_input = PolicyInput(
            subject=Subject(
                id="svc-forecast",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["dataset.query"],
                claims={"client_id": "svc-forecast"},
            ),
            resource=Resource(
                type=ResourceType.DATASET,
                id="ds-internal",
                attributes={"access_level": "internal"},
            ),
            action=Action(name="read", context={}),
        )
        
        decision = engine.evaluate_decision("celine.dataset.access", policy_input)
        
        assert decision.allowed is True

    def test_evaluate_service_write_without_admin_scope_denied(self, engine):
        """Test service write without admin scope is denied."""
        policy_input = PolicyInput(
            subject=Subject(
                id="svc-forecast",
                type=SubjectType.SERVICE,
                groups=[],
                scopes=["dataset.query"],
                claims={"client_id": "svc-forecast"},
            ),
            resource=Resource(
                type=ResourceType.DATASET,
                id="ds-internal",
                attributes={"access_level": "internal"},
            ),
            action=Action(name="write", context={}),
        )
        
        decision = engine.evaluate_decision("celine.dataset.access", policy_input)
        
        assert decision.allowed is False


class TestDecisionCache:
    """Tests for DecisionCache."""

    def test_cache_hit(self):
        """Test cache hit."""
        from celine_policies.models import Decision
        
        cache = DecisionCache(maxsize=100, ttl_seconds=300)
        decision = Decision(allowed=True, reason="test", policy="test.policy")
        
        cache.set("test.policy", {"subject": {"id": "user-1"}}, decision)
        
        result = cache.get("test.policy", {"subject": {"id": "user-1"}})
        assert result is not None
        assert result.allowed is True

    def test_cache_miss(self):
        """Test cache miss."""
        cache = DecisionCache(maxsize=100, ttl_seconds=300)
        
        result = cache.get("test.policy", {"subject": {"id": "user-1"}})
        assert result is None

    def test_cache_stats(self):
        """Test cache statistics."""
        from celine_policies.models import Decision
        
        cache = DecisionCache(maxsize=100, ttl_seconds=300)
        decision = Decision(allowed=True, reason="test", policy="test.policy")
        
        # Miss
        cache.get("test.policy", {"subject": {"id": "user-1"}})
        
        # Set
        cache.set("test.policy", {"subject": {"id": "user-1"}}, decision)
        
        # Hit
        cache.get("test.policy", {"subject": {"id": "user-1"}})
        
        stats = cache.stats
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["size"] == 1

    def test_cache_invalidation(self):
        """Test cache invalidation."""
        from celine_policies.models import Decision
        
        cache = DecisionCache(maxsize=100, ttl_seconds=300)
        decision = Decision(allowed=True, reason="test", policy="test.policy")
        
        cache.set("test.policy", {"subject": {"id": "user-1"}}, decision)
        cache.set("other.policy", {"subject": {"id": "user-1"}}, decision)
        
        # Invalidate specific policy
        count = cache.invalidate("test.policy")
        assert count == 1
        
        # Should still have other policy
        assert cache.stats["size"] == 1
        
        # Clear all
        cache.invalidate()
        assert cache.stats["size"] == 0
