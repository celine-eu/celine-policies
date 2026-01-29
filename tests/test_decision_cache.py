import time

from celine.policies.engine.cache import DecisionCache
from celine.policies.models import Decision


def test_cache_excludes_volatile_env_fields_from_key():
    cache = DecisionCache(maxsize=10, ttl_seconds=60)
    decision = Decision(allowed=True, reason="ok", policy="p")

    inp1 = {
        "subject": {"id": "u1"},
        "resource": {"type": "dataset", "id": "d1"},
        "action": {"name": "read"},
        "environment": {"timestamp": 1, "request_id": "a"},
    }
    inp2 = {
        "subject": {"id": "u1"},
        "resource": {"type": "dataset", "id": "d1"},
        "action": {"name": "read"},
        "environment": {"timestamp": 2, "request_id": "b"},
    }

    cache.set("p", inp1, decision)
    hit = cache.get("p", inp2)
    assert hit is not None
    assert hit.allowed is True


def test_cache_ttl_expires():
    cache = DecisionCache(maxsize=10, ttl_seconds=1)
    decision = Decision(allowed=True, reason="ok", policy="p")

    inp = {"subject": {"id": "u1"}, "resource": {"type": "dataset", "id": "d1"}, "action": {"name": "read"}}
    cache.set("p", inp, decision)
    assert cache.get("p", inp) is not None
    time.sleep(1.1)
    assert cache.get("p", inp) is None
