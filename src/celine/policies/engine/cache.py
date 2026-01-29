"""Decision cache for policy evaluation results."""

import hashlib
import json
import threading
import time
from typing import Any

import structlog
from cachetools import TTLCache

from ..models import Decision

logger = structlog.get_logger()


class DecisionCache:
    """LRU + TTL cache for policy decisions.

    Thread-safe implementation using cachetools.
    """

    def __init__(self, maxsize: int = 10000, ttl_seconds: int = 300):
        """Initialize the cache.

        Args:
            maxsize: Maximum number of entries
            ttl_seconds: Time-to-live in seconds
        """
        self._cache: TTLCache[str, Decision] = TTLCache(maxsize=maxsize, ttl=ttl_seconds)
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def get(self, policy: str, input_data: dict[str, Any]) -> Decision | None:
        """Get a cached decision.

        Args:
            policy: Policy package
            input_data: Policy input (volatile fields will be excluded)

        Returns:
            Cached Decision or None
        """
        key = self._make_key(policy, input_data)
        with self._lock:
            result = self._cache.get(key)
            if result is not None:
                self._hits += 1
                logger.debug("Cache hit", policy=policy, key=key[:16])
            else:
                self._misses += 1
            return result

    def set(self, policy: str, input_data: dict[str, Any], decision: Decision) -> None:
        """Cache a decision.

        Args:
            policy: Policy package
            input_data: Policy input
            decision: Decision to cache
        """
        key = self._make_key(policy, input_data)
        with self._lock:
            self._cache[key] = decision
            logger.debug("Cache set", policy=policy, key=key[:16])

    def invalidate(self, policy: str | None = None) -> int:
        """Invalidate cache entries.

        Args:
            policy: If provided, only invalidate entries for this policy.
                   If None, clear entire cache.

        Returns:
            Number of entries invalidated
        """
        with self._lock:
            if policy is None:
                count = len(self._cache)
                self._cache.clear()
                logger.info("Cache cleared", entries=count)
                return count

            # Partial invalidation by policy prefix
            keys_to_remove = [k for k in self._cache if k.startswith(f"{policy}:")]
            for key in keys_to_remove:
                del self._cache[key]
            logger.info("Cache invalidated", policy=policy, entries=len(keys_to_remove))
            return len(keys_to_remove)

    @property
    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            hit_rate = self._hits / total if total > 0 else 0.0
            return {
                "size": len(self._cache),
                "maxsize": self._cache.maxsize,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(hit_rate, 3),
            }

    def _make_key(self, policy: str, input_data: dict[str, Any]) -> str:
        """Generate cache key from policy and input.

        Excludes volatile fields (timestamp, request_id) from the hash.
        """
        # Extract stable parts of input
        stable_input = self._extract_stable_input(input_data)
        content = f"{policy}:{json.dumps(stable_input, sort_keys=True)}"
        return f"{policy}:{hashlib.sha256(content.encode()).hexdigest()[:32]}"

    def _extract_stable_input(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Extract cache-stable fields from input.

        Removes volatile fields that shouldn't affect caching.
        """
        result = {}

        # Copy subject (stable)
        if "subject" in input_data:
            result["subject"] = input_data["subject"]

        # Copy resource (stable)
        if "resource" in input_data:
            result["resource"] = input_data["resource"]

        # Copy action (stable)
        if "action" in input_data:
            result["action"] = input_data["action"]

        # Exclude environment (contains timestamp, request_id)
        # But include any stable environment fields if needed
        if "environment" in input_data:
            env = input_data["environment"]
            stable_env = {
                k: v
                for k, v in env.items()
                if k not in ("timestamp", "request_id", "trace_id")
            }
            if stable_env:
                result["environment"] = stable_env

        return result


class CachedPolicyEngine:
    """Policy engine with integrated caching."""

    def __init__(
        self,
        engine: Any,  # PolicyEngine - avoiding circular import
        cache: DecisionCache | None = None,
        cache_enabled: bool = True,
    ):
        """Initialize cached engine.

        Args:
            engine: The underlying PolicyEngine
            cache: Optional cache instance (creates default if None)
            cache_enabled: Whether caching is enabled
        """
        self._engine = engine
        self._cache = cache or DecisionCache()
        self._cache_enabled = cache_enabled

    def evaluate_decision(
        self,
        policy_package: str,
        policy_input: Any,  # PolicyInput
        skip_cache: bool = False,
    ) -> tuple[Decision, bool]:
        """Evaluate policy with caching.

        Args:
            policy_package: Policy package path
            policy_input: Policy input
            skip_cache: If True, bypass cache

        Returns:
            Tuple of (Decision, was_cached)
        """
        input_dict = self._engine._build_input(policy_input)

        # Try cache first
        if self._cache_enabled and not skip_cache:
            cached = self._cache.get(policy_package, input_dict)
            if cached is not None:
                return cached, True

        # Evaluate policy
        decision = self._engine.evaluate_decision(policy_package, policy_input)

        # Cache result
        if self._cache_enabled and not skip_cache:
            self._cache.set(policy_package, input_dict, decision)

        return decision, False

    def invalidate_cache(self, policy: str | None = None) -> int:
        """Invalidate cache entries."""
        return self._cache.invalidate(policy)

    @property
    def cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        return self._cache.stats

    # Delegate other methods to underlying engine
    def __getattr__(self, name: str) -> Any:
        return getattr(self._engine, name)
