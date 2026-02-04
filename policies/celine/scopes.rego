# METADATA
# title: Scope Matching
# description: Shared scope matching logic - imported by all policies
# scope: package
package celine.scopes

import rego.v1

# =============================================================================
# SCOPE MATCHING
# =============================================================================
#
# Scope convention: {service}.{resource}.{action}
#
# Matching rules:
#   1. Exact match: "dt.simulation.read" matches "dt.simulation.read"
#   2. Admin override: "dt.admin" matches any "dt.*"
#   3. Resource wildcard: "dt.simulation.*" matches "dt.simulation.{read,write,run}"
#
# =============================================================================

# Check if subject has required scope
has_scope(required) if {
    some have in input.subject.scopes
    scope_matches(have, required)
}

# Check if subject has any of the required scopes
has_any_scope(required_list) if {
    some required in required_list
    has_scope(required)
}

# Exact match
scope_matches(have, want) if {
    have == want
}

# Admin override: {service}.admin matches {service}.**
scope_matches(have, want) if {
    endswith(have, ".admin")
    service := trim_suffix(have, ".admin")
    startswith(want, concat("", [service, "."]))
}

# Resource wildcard: {service}.{resource}.* matches {service}.{resource}.{action}
scope_matches(have, want) if {
    endswith(have, ".*")
    prefix := trim_suffix(have, "*")
    startswith(want, prefix)
}

# =============================================================================
# SUBJECT HELPERS
# =============================================================================

# Check if subject is a service (machine-to-machine)
is_service if {
    input.subject.type == "service"
}

# Check if subject is a user
is_user if {
    input.subject.type == "user"
}

# Check if subject is anonymous/null
is_anonymous if {
    input.subject == null
}

is_anonymous if {
    input.subject.type == "anonymous"
}
