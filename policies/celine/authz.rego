# METADATA
# title: Generic Authorization (Fallback)
# description: Default scope-based authorization for resources without specialized policies
# scope: package
# entrypoint: true
package celine.authz

import rego.v1

import data.celine.scopes

# =============================================================================
# GENERIC AUTHORIZATION
# =============================================================================
#
# This is the FALLBACK policy used when no specialized policy exists.
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

# =============================================================================
# AUTHORIZATION RULE
# =============================================================================

allow if {
    scopes.is_service
    scopes.has_scope(required_scope)
}

reason := "authorized" if {
    scopes.is_service
    scopes.has_scope(required_scope)
}

# =============================================================================
# SCOPE DERIVATION
# =============================================================================

# Full path: {type}.{resource_type}.{action}
required_scope := scope if {
    rt := input.resource.attributes.resource_type
    rt != null
    rt != ""
    scope := concat(".", [input.resource.type, rt, input.action.name])
}

# Fallback: {type}.{action}
required_scope := scope if {
    not input.resource.attributes.resource_type
    scope := concat(".", [input.resource.type, input.action.name])
}

required_scope := scope if {
    input.resource.attributes.resource_type == ""
    scope := concat(".", [input.resource.type, input.action.name])
}

# =============================================================================
# DENIAL REASONS
# =============================================================================

reason := "anonymous access denied" if {
    not allow
    scopes.is_anonymous
}

reason := "missing required scope" if {
    not allow
    scopes.is_service
}
