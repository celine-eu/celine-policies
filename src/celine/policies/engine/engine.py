"""Policy engine using regorus (embedded Rego evaluator)."""

import json
import threading
import time
from pathlib import Path
from typing import Any

from regorus import Engine

import logging

from celine.policies.models import Decision, FilterPredicate, PolicyInput

logger = logging.getLogger(__name__)


class PolicyEngineError(Exception):
    """Error during policy evaluation."""

    pass


class PolicyEngine:
    """Thread-safe wrapper around regorus for policy evaluation.

    Supports hot-reload via copy-on-write pattern.
    """

    cache_stats = None

    def __init__(self, policies_dir: Path, data_dir: Path | None = None):
        """Initialize the policy engine.

        Args:
            policies_dir: Directory containing .rego policy files
            data_dir: Directory containing data.json files (optional)
        """
        self._policies_dir = policies_dir
        self._data_dir = data_dir
        self._engine = Engine()
        self._lock = threading.RLock()
        self._loaded = False
        self._policy_count = 0
        self._data_count = 0

    def load(self) -> None:
        """Load all policies and data files."""
        with self._lock:
            self._engine = Engine()
            self._policy_count = 0
            self._data_count = 0

            # Load all .rego files recursively
            if self._policies_dir.exists():
                for rego_file in self._policies_dir.rglob("*.rego"):
                    # Skip test files
                    if rego_file.name.endswith("_test.rego"):
                        continue
                    try:
                        self._engine.add_policy_from_file(str(rego_file))
                        self._policy_count += 1
                        logger.debug("Loaded policy file=%s", rego_file)
                    except Exception as e:
                        logger.error(
                            "Failed to load policy file=%s error=%s", rego_file, e
                        )
                        raise PolicyEngineError(
                            f"Failed to load {rego_file}: {e}"
                        ) from e

            # Load all data.json files
            if self._data_dir and self._data_dir.exists():
                for data_file in self._data_dir.rglob("*.json"):
                    try:
                        # Derive data path from file location
                        # e.g., data/celine/roles.json -> data.celine.roles
                        rel_path = data_file.relative_to(self._data_dir)
                        data_path = "data." + ".".join(rel_path.with_suffix("").parts)
                        self._engine.add_data_from_json_file(str(data_file))
                        self._data_count += 1
                        logger.debug(
                            "Loaded data file=%s path=%s", data_file, data_path
                        )
                    except Exception as e:
                        logger.error(
                            "Failed to load data file=%s error=%s", data_file, e
                        )
                        raise PolicyEngineError(
                            f"Failed to load {data_file}: {e}"
                        ) from e

            self._loaded = True
            logger.info(
                "Policy engine loaded policies=%s data_files=%s",
                self._policy_count,
                self._data_count,
            )

    def reload(self) -> None:
        """Hot-reload policies (thread-safe)."""
        logger.info("Reloading policies")
        new_engine = PolicyEngine(self._policies_dir, self._data_dir)
        new_engine.load()

        with self._lock:
            self._engine = new_engine._engine
            self._policy_count = new_engine._policy_count
            self._data_count = new_engine._data_count

        logger.info("Policies reloaded successfully")

    @property
    def is_loaded(self) -> bool:
        """Check if policies are loaded."""
        return self._loaded

    @property
    def policy_count(self) -> int:
        """Number of loaded policies."""
        return self._policy_count

    def evaluate(self, rule: str, input_data: dict[str, Any]) -> dict[str, Any]:
        """Evaluate a policy rule.

        Args:
            rule: Full rule path (e.g., "data.celine.dataset.access.allow")
            input_data: Input data for the policy

        Returns:
            Policy evaluation result
        """
        if not self._loaded:
            raise PolicyEngineError("Policies not loaded. Call load() first.")

        with self._lock:
            try:
                # Set input data
                self._engine.set_input(input_data)

                # Evaluate rule
                result = self._engine.eval_rule(rule)

                # Parse result
                if result is None:
                    return {"value": None}

                return {"value": result}

            except Exception as e:
                logger.error("Policy evaluation failed rule=%s error=%s", rule, e)
                raise PolicyEngineError(f"Evaluation failed for {rule}: {e}") from e

    def evaluate_decision(
        self,
        policy_package: str,
        policy_input: PolicyInput,
    ) -> Decision:
        """Evaluate a policy and return a Decision object.

        Args:
            policy_package: Policy package (e.g., "celine.dataset.access")
            policy_input: Structured policy input

        Returns:
            Decision object
        """
        start_time = time.perf_counter()

        # Convert input to dict for OPA
        input_dict = self._build_input(policy_input)

        # Evaluate allow rule
        allow_rule = f"data.{policy_package}.allow"
        allow_result = self.evaluate(allow_rule, input_dict)
        allowed = bool(allow_result.get("value", False))

        # Try to get reason
        reason = ""
        try:
            reason_rule = f"data.{policy_package}.reason"
            reason_result = self.evaluate(reason_rule, input_dict)
            reason = str(reason_result.get("value", ""))
        except PolicyEngineError:
            pass  # Reason is optional

        # Try to get filters (for row-level policies)
        filters: list[FilterPredicate] = []
        try:
            filters_rule = f"data.{policy_package}.filters"
            filters_result = self.evaluate(filters_rule, input_dict)
            raw_filters = filters_result.get("value", [])
            if isinstance(raw_filters, list):
                filters = [
                    FilterPredicate(**f) for f in raw_filters if isinstance(f, dict)
                ]
        except PolicyEngineError:
            pass  # Filters are optional

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        logger.debug(
            "Policy evaluated package=%s allowed=%s latency_ms=%s",
            policy_package,
            allowed,
            round(elapsed_ms, 2),
        )

        return Decision(
            allowed=allowed,
            reason=reason,
            policy=policy_package,
            filters=filters,
            cached=False,
        )

    def build_input_dict(self, policy_input: PolicyInput) -> dict[str, Any]:
        return self._build_input(policy_input)

    def _build_input(self, policy_input: PolicyInput) -> dict[str, Any]:
        """Build OPA input from PolicyInput."""
        result: dict[str, Any] = {
            "resource": {
                "type": policy_input.resource.type.value,
                "id": policy_input.resource.id,
                "attributes": policy_input.resource.attributes,
            },
            "action": {
                "name": policy_input.action.name,
                "context": policy_input.action.context,
            },
            "environment": policy_input.environment,
        }

        if policy_input.subject:
            result["subject"] = {
                "id": policy_input.subject.id,
                "type": policy_input.subject.type.value,
                "groups": policy_input.subject.groups,
                "scopes": policy_input.subject.scopes,
                "claims": policy_input.subject.claims,
            }
        else:
            result["subject"] = None

        return result
