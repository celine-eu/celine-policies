"""Policy engine using regorus (embedded Rego evaluator)."""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

from regorus import Engine

from celine.policies.models import Decision, FilterPredicate, PolicyInput

logger = logging.getLogger(__name__)


class PolicyEngineError(Exception):
    """Base exception for policy engine errors."""

    pass


class PolicyEngine:
    """Embedded OPA policy engine using regorus.

    Thread-safe policy evaluation with support for:
    - Loading policies from directory
    - Loading data from JSON files
    - Hot reload of policies
    - Package existence checking for routing
    """

    def __init__(
        self,
        policies_dir: Path | str | None = None,
        data_dir: Path | str | None = None,
    ):
        self._policies_dir = Path(policies_dir) if policies_dir else None
        self._data_dir = Path(data_dir) if data_dir else None
        self._engine: Engine | None = None
        self._lock = threading.RLock()
        self._loaded = False
        self._policy_count = 0
        self._known_packages: set[str] = set()

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def policy_count(self) -> int:
        return self._policy_count

    def load(self) -> None:
        """Load policies and data from configured directories."""
        with self._lock:
            self._engine = Engine()
            self._policy_count = 0
            self._known_packages = set()

            if self._policies_dir and self._policies_dir.exists():
                self._load_policies(self._policies_dir)

            if self._data_dir and self._data_dir.exists():
                self._load_data(self._data_dir)

            self._loaded = True
            logger.info(
                "Policy engine loaded: %d policies, packages: %s",
                self._policy_count,
                sorted(self._known_packages),
            )

    def reload(self) -> None:
        """Reload all policies and data."""
        logger.info("Reloading policies...")
        self.load()

    def _load_policies(self, directory: Path) -> None:
        """Recursively load .rego files from directory."""
        for rego_file in directory.rglob("*.rego"):
            if rego_file.name.endswith("_test.rego"):
                continue  # Skip test files in production

            try:
                content = rego_file.read_text()
                self._engine.add_policy(str(rego_file), content)
                self._policy_count += 1

                # Extract package name for routing
                package_name = self._extract_package_name(content)
                if package_name:
                    self._known_packages.add(package_name)

                logger.debug("Loaded policy: %s (package: %s)", rego_file, package_name)
            except Exception as e:
                logger.error("Failed to load policy %s: %s", rego_file, e)
                raise PolicyEngineError(f"Failed to load {rego_file}: {e}") from e

    def _extract_package_name(self, content: str) -> str | None:
        """Extract package name from Rego policy content."""
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("package "):
                return line.split()[1].strip()
        return None

    def _load_data(self, directory: Path) -> None:
        """Load JSON data files into the engine."""
        for json_file in directory.rglob("*.json"):
            try:
                content = json_file.read_text()
                data = json.loads(content)

                # Derive data path from filename
                # e.g., data/celine.json -> data.celine
                relative = json_file.relative_to(directory)
                path_parts = list(relative.parts[:-1]) + [json_file.stem]
                data_path = "data." + ".".join(path_parts)

                self._engine.add_data_json(content)
                logger.debug("Loaded data: %s -> %s", json_file, data_path)
            except Exception as e:
                logger.error("Failed to load data %s: %s", json_file, e)
                raise PolicyEngineError(f"Failed to load {json_file}: {e}") from e

    def has_package(self, package: str) -> bool:
        """Check if a policy package exists.

        Used for routing decisions - try specific policy first,
        fall back to generic if not found.

        Args:
            package: Package name (e.g., "celine.dataset")

        Returns:
            True if package exists, False otherwise
        """
        return package in self._known_packages

    def get_packages(self) -> list[str]:
        """Get list of all loaded policy packages."""
        return sorted(self._known_packages)

    def evaluate(self, query: str, input_data: dict[str, Any]) -> Any:
        """Evaluate a Rego query with input data.

        Args:
            query: Rego query path (e.g., "data.celine.authz.allow")
            input_data: Input data for the query

        Returns:
            Query result
        """
        if not self._loaded:
            raise PolicyEngineError("Policy engine not loaded")

        with self._lock:
            self._engine.set_input_json(json.dumps(input_data))
            result = self._engine.eval_query(query)
            return result

    def evaluate_decision(
        self,
        policy_package: str,
        policy_input: PolicyInput,
    ) -> Decision:
        """Evaluate a policy and return a Decision.

        Args:
            policy_package: Policy package (e.g., "celine.dataset")
            policy_input: Structured policy input

        Returns:
            Decision with allowed, reason, filters
        """
        if not self._loaded:
            raise PolicyEngineError("Policy engine not loaded")

        input_dict = self._build_input(policy_input)

        with self._lock:
            self._engine.set_input_json(json.dumps(input_dict))

            # Query allow
            allow_query = f"data.{policy_package}.allow"
            allow_result = self._engine.eval_query(allow_query)
            allowed = self._extract_bool(allow_result, False)

            # Query reason
            reason_query = f"data.{policy_package}.reason"
            reason_result = self._engine.eval_query(reason_query)
            reason = self._extract_string(reason_result, "")

            # Query filters (optional)
            filters: list[FilterPredicate] = []
            try:
                filters_query = f"data.{policy_package}.filters"
                filters_result = self._engine.eval_query(filters_query)
                filters = self._extract_filters(filters_result)
            except Exception:
                pass  # Filters are optional

        return Decision(
            allowed=allowed,
            reason=reason,
            policy=policy_package,
            filters=filters,
            cached=False,
        )

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

    def _extract_bool(self, result: Any, default: bool) -> bool:
        """Extract boolean from query result."""
        if isinstance(result, list) and len(result) > 0:
            item = result[0]
            if isinstance(item, dict) and "expressions" in item:
                exprs = item["expressions"]
                if exprs and len(exprs) > 0:
                    return bool(exprs[0].get("value", default))
        return default

    def _extract_string(self, result: Any, default: str) -> str:
        """Extract string from query result."""
        if isinstance(result, list) and len(result) > 0:
            item = result[0]
            if isinstance(item, dict) and "expressions" in item:
                exprs = item["expressions"]
                if exprs and len(exprs) > 0:
                    value = exprs[0].get("value")
                    if isinstance(value, str):
                        return value
        return default

    def _extract_filters(self, result: Any) -> list[FilterPredicate]:
        """Extract filter predicates from query result."""
        filters = []
        if isinstance(result, list) and len(result) > 0:
            item = result[0]
            if isinstance(item, dict) and "expressions" in item:
                exprs = item["expressions"]
                if exprs and len(exprs) > 0:
                    value = exprs[0].get("value")
                    if isinstance(value, list):
                        for f in value:
                            if isinstance(f, dict):
                                filters.append(
                                    FilterPredicate(
                                        field=f.get("field", ""),
                                        operator=f.get("operator", ""),
                                        value=f.get("value"),
                                    )
                                )
        return filters
