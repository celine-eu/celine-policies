"""Policy service API layer.

This module centralizes:
- policy package resolution
- evaluation (with caching)
- audit logging
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from celine.policies.audit import AuditLogger
from celine.policies.engine import CachedPolicyEngine
from celine.policies.models import Decision, PolicyInput, Resource


class PolicyPackageError(ValueError):
    pass


RESOURCE_POLICY_MAP: dict[str, str] = {
    "dataset": "celine.dataset.access",
    "pipeline": "celine.pipeline.state",
    "dt": "celine.dt.access",
    "topic": "celine.mqtt.acl",
    "userdata": "celine.userdata.access",
}


def policy_package_for_resource(resource: Resource) -> str:
    resource_type = resource.type.value if hasattr(resource.type, "value") else str(resource.type)
    pkg = RESOURCE_POLICY_MAP.get(resource_type)
    if not pkg:
        raise PolicyPackageError(f"Unknown resource type: {resource_type}")
    return pkg


@dataclass(frozen=True)
class EvaluationResult:
    decision: Decision
    cached: bool
    latency_ms: float


class PolicyAPI:
    def __init__(self, *, engine: CachedPolicyEngine, audit: AuditLogger):
        self._engine = engine
        self._audit = audit

    def evaluate(
        self,
        *,
        request_id: str,
        policy_package: str,
        policy_input: PolicyInput,
        source_service: str | None = None,
        skip_cache: bool = False,
    ) -> EvaluationResult:
        start = time.perf_counter()
        try:
            decision, cached = self._engine.evaluate_decision(
                policy_package, policy_input, skip_cache=skip_cache
            )
            latency_ms = (time.perf_counter() - start) * 1000
            self._audit.log_decision(
                request_id=request_id,
                decision=decision,
                policy_input=policy_input,
                latency_ms=latency_ms,
                cached=cached,
                source_service=source_service,
            )
            return EvaluationResult(decision=decision, cached=cached, latency_ms=latency_ms)
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            self._audit.log_error(
                request_id=request_id,
                error=str(e),
                policy_input=policy_input,
                source_service=source_service,
            )
            raise

    def evaluate_for_resource(
        self,
        *,
        request_id: str,
        policy_input: PolicyInput,
        source_service: str | None = None,
        skip_cache: bool = False,
    ) -> EvaluationResult:
        pkg = policy_package_for_resource(policy_input.resource)
        return self.evaluate(
            request_id=request_id,
            policy_package=pkg,
            policy_input=policy_input,
            source_service=source_service,
            skip_cache=skip_cache,
        )
