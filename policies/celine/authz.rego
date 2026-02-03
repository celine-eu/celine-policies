# METADATA
# title: Unified API Authorization
# description: Single policy for all service API authorization via /authorize endpoint
# scope: package
# entrypoint: true
# authors:
#   - CELINE Platform Team
package celine.authz

import rego.v1

import data.celine.scopes

# =============================================================================
# UNIFIED API AUTHORIZATION
# =============================================================================
#
# All services call POST /authorize with:
#   {
#     "resource": {"type": "dt", "id": "...", "attributes": {"resource_type": "simulation"}},
#     "action": {"name": "read"}
#   }
#
# Scope derivation:
#   {resource.type}.{resource.attributes.resource_type}.{action.name}
#   → dt.simulation.read
#
# Fallback (no resource_type):
#   {resource.type}.{action.name}
#   → dataset.query
#
# =============================================================================

default allow := false
default reason := "unauthorized"

# -----------------------------------------------------------------------------
# MAIN AUTHORIZATION RULE
# -----------------------------------------------------------------------------

allow if {
    scopes.is_service
    required := required_scope
    scopes.has_scope(required)
}

reason := "authorized" if {
    scopes.is_service
    required := required_scope
    scopes.has_scope(required)
}

# -----------------------------------------------------------------------------
# SCOPE DERIVATION
# -----------------------------------------------------------------------------

# Full path: {service}.{resource_type}.{action}
required_scope := scope if {
    rt := input.resource.attributes.resource_type
    rt != null
    rt != ""
    scope := concat(".", [input.resource.type, rt, input.action.name])
}

# Fallback: {service}.{action}
required_scope := scope if {
    not input.resource.attributes.resource_type
    scope := concat(".", [input.resource.type, input.action.name])
}

# Fallback for empty resource_type
required_scope := scope if {
    input.resource.attributes.resource_type == ""
    scope := concat(".", [input.resource.type, input.action.name])
}

# -----------------------------------------------------------------------------
# DENIAL REASONS
# -----------------------------------------------------------------------------

reason := "anonymous access denied" if {
    not allow
    scopes.is_anonymous
}

reason := "missing required scope" if {
    not allow
    scopes.is_service
    required_scope
}

reason := "invalid request" if {
    not allow
    not scopes.is_anonymous
    not scopes.is_service
}

# -----------------------------------------------------------------------------
# INTROSPECTION
# -----------------------------------------------------------------------------

# Expose derived scope for debugging/logging
derived_scope := required_scope
