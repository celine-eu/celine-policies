package celine.authz_test

import rego.v1

import data.celine.authz

# =============================================================================
# BASIC SCOPE CHECK
# =============================================================================

test_allow_with_exact_scope if {
    authz.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dt.simulation.read"]},
        "resource": {"type": "dt", "id": "sim-123", "attributes": {"resource_type": "simulation"}},
        "action": {"name": "read"},
    }
}

test_allow_with_admin_scope if {
    authz.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dt.admin"]},
        "resource": {"type": "dt", "id": "sim-123", "attributes": {"resource_type": "simulation"}},
        "action": {"name": "write"},
    }
}

test_allow_with_wildcard_scope if {
    authz.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dt.simulation.*"]},
        "resource": {"type": "dt", "id": "sim-123", "attributes": {"resource_type": "simulation"}},
        "action": {"name": "run"},
    }
}

test_deny_missing_scope if {
    not authz.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dt.values.read"]},
        "resource": {"type": "dt", "id": "sim-123", "attributes": {"resource_type": "simulation"}},
        "action": {"name": "read"},
    }
}

test_deny_cross_service if {
    not authz.allow with input as {
        "subject": {"type": "service", "id": "svc-pipelines", "scopes": ["pipeline.status.read"]},
        "resource": {"type": "dt", "id": "sim-123", "attributes": {"resource_type": "simulation"}},
        "action": {"name": "read"},
    }
}

# =============================================================================
# FALLBACK SCOPE (no resource_type)
# =============================================================================

test_fallback_scope if {
    authz.allow with input as {
        "subject": {"type": "service", "id": "svc-custom", "scopes": ["custom.execute"]},
        "resource": {"type": "custom", "id": "item-1", "attributes": {}},
        "action": {"name": "execute"},
    }
}

test_required_scope_full_path if {
    authz.required_scope == "dt.simulation.read" with input as {
        "resource": {"type": "dt", "attributes": {"resource_type": "simulation"}},
        "action": {"name": "read"},
    }
}

test_required_scope_fallback if {
    authz.required_scope == "custom.execute" with input as {
        "resource": {"type": "custom", "attributes": {}},
        "action": {"name": "execute"},
    }
}

# =============================================================================
# ANONYMOUS DENIAL
# =============================================================================

test_deny_anonymous if {
    not authz.allow with input as {
        "subject": null,
        "resource": {"type": "dt", "id": "sim-123", "attributes": {"resource_type": "simulation"}},
        "action": {"name": "read"},
    }
}

test_reason_anonymous if {
    authz.reason == "anonymous access denied" with input as {
        "subject": null,
        "resource": {"type": "dt", "attributes": {"resource_type": "simulation"}},
        "action": {"name": "read"},
    }
}

test_reason_missing_scope if {
    authz.reason == "missing required scope" with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["other.scope"]},
        "resource": {"type": "dt", "attributes": {"resource_type": "simulation"}},
        "action": {"name": "read"},
    }
}
