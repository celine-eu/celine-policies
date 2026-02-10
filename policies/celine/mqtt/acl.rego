# METADATA
# title: MQTT ACL Policy
# description: Topic-based authorization deriving required scopes from topic patterns
# scope: package
# entrypoint: true
package celine.mqtt.acl

import rego.v1

import data.celine.scopes

# =============================================================================
# MQTT AUTHORIZATION
# =============================================================================
#
# Topic pattern: celine/{service}/{resource}/...
#
# Authorization flow:
#   1. Parse topic to extract service and resource
#   2. Map MQTT action (subscribe/publish) to scope action (read/write)
#   3. Derive required scope: {service}.{resource}.{action}
#   4. Check if subject has scope (with admin/wildcard expansion)
#
# =============================================================================

default allow := false
default reason := "unauthorized"

# =============================================================================
# MAIN RULES
# =============================================================================

allow if {
    data.celine.scopes.is_service
    required := required_scope(input.resource.id, input.action.name)
    data.celine.scopes.has_scope(required)
}

reason := "service authorized via scope" if {
    data.celine.scopes.is_service
    required := required_scope(input.resource.id, input.action.name)
    data.celine.scopes.has_scope(required)
}

# Admin scope for service always wins
allow if {
    data.celine.scopes.is_service
    parsed := parse_topic(input.resource.id)
    admin_scope := concat(".", [parsed.service, "admin"])
    data.celine.scopes.has_scope(admin_scope)
}

reason := "service authorized via admin scope" if {
    data.celine.scopes.is_service
    parsed := parse_topic(input.resource.id)
    admin_scope := concat(".", [parsed.service, "admin"])
    data.celine.scopes.has_scope(admin_scope)
}

# =============================================================================
# TOPIC PARSING
# =============================================================================

parse_topic(topic) := result if {
    parts := split(topic, "/")
    count(parts) >= 3
    parts[0] == "celine"
    result := {
        "service": parts[1],
        "resource": parts[2],
    }
}

parse_topic(topic) := result if {
    parts := split(topic, "/")
    count(parts) == 2
    parts[0] == "celine"
    result := {
        "service": parts[1],
        "resource": "",
    }
}

# =============================================================================
# SCOPE DERIVATION
# =============================================================================

mqtt_action_map := {
    "subscribe": "read",
    "read": "read",
    "publish": "write",
}

required_scope(topic, mqtt_action) := scope if {
    parsed := parse_topic(topic)
    parsed.resource != ""
    scope_action := mqtt_action_map[mqtt_action]
    scope := concat(".", [parsed.service, parsed.resource, scope_action])
}

required_scope(topic, mqtt_action) := scope if {
    parsed := parse_topic(topic)
    parsed.resource == ""
    scope := concat(".", [parsed.service, "admin"])
}

# =============================================================================
# DENIAL REASONS
# =============================================================================

reason := "anonymous access denied" if {
    not allow
    data.celine.scopes.is_anonymous
}

reason := "invalid topic format" if {
    not allow
    not data.celine.scopes.is_anonymous
    not parse_topic(input.resource.id)
}

reason := "missing required scope" if {
    not allow
    data.celine.scopes.is_service
    parse_topic(input.resource.id)
}

# =============================================================================
# INTROSPECTION
# =============================================================================

derived_scope := required_scope(input.resource.id, input.action.name)
parsed_topic := parse_topic(input.resource.id)
