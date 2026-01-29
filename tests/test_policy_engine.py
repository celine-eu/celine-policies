from pathlib import Path

import pytest

from celine.policies.engine.engine import PolicyEngine, PolicyEngineError
from celine.policies.models import Action, PolicyInput, Resource, ResourceType, Subject, SubjectType


def _write_policy(dir: Path):
    # A minimal policy package with allow + reason
    (dir / "celine").mkdir(parents=True, exist_ok=True)
    (dir / "celine" / "dataset_access.rego").write_text(
        '''
package celine.dataset.access

import rego.v1

default allow := false

allow := true if {
  input.action.name == "read"
}

reason := "ok"
filters := []
'''
    )


def test_policy_engine_load_and_evaluate_decision(tmp_path: Path):
    policies = tmp_path / "policies"
    policies.mkdir()
    _write_policy(policies)

    engine = PolicyEngine(policies_dir=policies, data_dir=None)
    engine.load()
    assert engine.is_loaded is True
    assert engine.policy_count == 1

    policy_input = PolicyInput(
        subject=Subject(id="u1", type=SubjectType.USER, groups=[], scopes=[], claims={}),
        resource=Resource(type=ResourceType.DATASET, id="ds1", attributes={}),
        action=Action(name="read", context={}),
        environment={"timestamp": 1, "request_id": "r1"},
    )

    decision = engine.evaluate_decision("celine.dataset.access", policy_input)

    print("decision", decision)

    assert decision.allowed is True
    assert decision.reason == "ok"


def test_policy_engine_raises_when_not_loaded(tmp_path: Path):
    policies = tmp_path / "policies"
    policies.mkdir()
    engine = PolicyEngine(policies_dir=policies, data_dir=None)

    with pytest.raises(PolicyEngineError):
        engine.evaluate("data.x.allow", {"a": 1})
