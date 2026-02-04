package celine.scopes_test

import rego.v1

import data.celine.scopes

# =============================================================================
# EXACT MATCH
# =============================================================================

test_exact_match if {
    scopes.scope_matches("dt.simulation.read", "dt.simulation.read")
}

test_exact_no_match if {
    not scopes.scope_matches("dt.simulation.read", "dt.simulation.write")
}

# =============================================================================
# ADMIN OVERRIDE
# =============================================================================

test_admin_matches_any if {
    scopes.scope_matches("dt.admin", "dt.simulation.read")
}

test_admin_matches_nested if {
    scopes.scope_matches("dt.admin", "dt.values.write")
}

test_admin_no_cross_service if {
    not scopes.scope_matches("dt.admin", "pipeline.status.read")
}

# =============================================================================
# WILDCARD
# =============================================================================

test_wildcard_matches if {
    scopes.scope_matches("dt.simulation.*", "dt.simulation.read")
}

test_wildcard_matches_run if {
    scopes.scope_matches("dt.simulation.*", "dt.simulation.run")
}

test_wildcard_no_cross_resource if {
    not scopes.scope_matches("dt.simulation.*", "dt.values.read")
}

# =============================================================================
# HAS_SCOPE
# =============================================================================

test_has_scope_exact if {
    scopes.has_scope("dt.simulation.read") with input as {
        "subject": {"type": "service", "scopes": ["dt.simulation.read"]}
    }
}

test_has_scope_via_admin if {
    scopes.has_scope("dt.simulation.read") with input as {
        "subject": {"type": "service", "scopes": ["dt.admin"]}
    }
}

test_has_scope_missing if {
    not scopes.has_scope("dt.simulation.write") with input as {
        "subject": {"type": "service", "scopes": ["dt.simulation.read"]}
    }
}

# =============================================================================
# SUBJECT TYPE
# =============================================================================

test_is_service if {
    scopes.is_service with input as {"subject": {"type": "service"}}
}

test_is_user if {
    scopes.is_user with input as {"subject": {"type": "user"}}
}

test_is_anonymous_null if {
    scopes.is_anonymous with input as {"subject": null}
}
