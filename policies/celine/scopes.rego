# METADATA
# title: Scope Matching
# description: Core scope matching logic with wildcard and admin override support
# scope: package
# authors:
#   - CELINE Platform Team
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
# HELPERS
# =============================================================================

# Extract service from scope
service_from_scope(scope) := service if {
    parts := split(scope, ".")
    count(parts) >= 1
    service := parts[0]
}

# Extract resource from scope (if present)
resource_from_scope(scope) := resource if {
    parts := split(scope, ".")
    count(parts) >= 2
    resource := parts[1]
}

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
