# METADATA
# title: MQTT ACL Policy
# description: Topic-based authorization deriving required scopes from topic patterns
# scope: package
# entrypoint: true
# authors:
#   - CELINE Platform Team
package celine.mqtt

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

# -----------------------------------------------------------------------------
# MAIN RULES
# -----------------------------------------------------------------------------

# Service authorization via derived scope
allow if {
    scopes.is_service
    required := required_scope(input.resource.id, input.action.name)
    scopes.has_scope(required)
}

reason := "service authorized via scope" if {
    scopes.is_service
    required := required_scope(input.resource.id, input.action.name)
    scopes.has_scope(required)
}

# Service authorization via admin scope
allow if {
    scopes.is_service
    parsed := parse_topic(input.resource.id)
    admin_scope := concat(".", [parsed.service, "admin"])
    scopes.has_scope(admin_scope)
}

reason := "service authorized via admin scope" if {
    scopes.is_service
    parsed := parse_topic(input.resource.id)
    admin_scope := concat(".", [parsed.service, "admin"])
    scopes.has_scope(admin_scope)
}

# -----------------------------------------------------------------------------
# TOPIC PARSING
# -----------------------------------------------------------------------------

# Parse topic: celine/{service}/{resource}/... → {"service": x, "resource": y}
parse_topic(topic) := result if {
    parts := split(topic, "/")
    count(parts) >= 3
    parts[0] == "celine"
    result := {
        "service": parts[1],
        "resource": parts[2],
    }
}

# Fallback for short topics: celine/{service} → {"service": x, "resource": ""}
parse_topic(topic) := result if {
    parts := split(topic, "/")
    count(parts) == 2
    parts[0] == "celine"
    result := {
        "service": parts[1],
        "resource": "",
    }
}

# -----------------------------------------------------------------------------
# SCOPE DERIVATION
# -----------------------------------------------------------------------------

# Map MQTT action to scope action
mqtt_action_map := {
    "subscribe": "read",
    "read": "read",
    "publish": "write",
}

# Derive required scope from topic and MQTT action
required_scope(topic, mqtt_action) := scope if {
    parsed := parse_topic(topic)
    parsed.resource != ""
    scope_action := mqtt_action_map[mqtt_action]
    scope := concat(".", [parsed.service, parsed.resource, scope_action])
}

# For service-level topics (no resource), require admin
required_scope(topic, mqtt_action) := scope if {
    parsed := parse_topic(topic)
    parsed.resource == ""
    scope := concat(".", [parsed.service, "admin"])
}

# -----------------------------------------------------------------------------
# DENIAL REASONS
# -----------------------------------------------------------------------------

reason := "anonymous access denied" if {
    not allow
    scopes.is_anonymous
}

reason := "invalid topic format" if {
    not allow
    not scopes.is_anonymous
    not parse_topic(input.resource.id)
}

reason := "missing required scope" if {
    not allow
    scopes.is_service
    parse_topic(input.resource.id)
}

# -----------------------------------------------------------------------------
# INTROSPECTION (for debugging/logging)
# -----------------------------------------------------------------------------

# Expose derived scope for debugging
derived_scope := required_scope(input.resource.id, input.action.name)

# Expose parsed topic
parsed_topic := parse_topic(input.resource.id)
