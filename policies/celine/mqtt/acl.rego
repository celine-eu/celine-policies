# METADATA
# title: MQTT Topic ACL Policy
# description: Controls access to MQTT topics for pub/sub operations
# scope: package
# entrypoint: true
package celine.mqtt.acl

import rego.v1

import data.celine.common.subject

# Default deny
default allow := false

default reason := ""

# MQTT access types (from mosquitto-go-auth)
# 1 = subscribe, 2 = publish, 3 = subscribe+publish, 4 = subscribe literal

# =============================================================================
# TOPIC PATTERNS
# =============================================================================

# Topic structure: celine/{domain}/{resource_type}/{resource_id}/{channel}
# Examples:
#   celine/twins/twin-123/telemetry
#   celine/twins/twin-123/commands
#   celine/pipelines/pipe-456/status
#   celine/datasets/ds-789/updates
#   celine/system/alerts

# =============================================================================
# SYSTEM TOPICS
# =============================================================================

# Admins can subscribe to all system topics
allow if {
	input.action.name == "subscribe"
	startswith(input.resource.id, "celine/system/")
	subject.is_user
	subject.has_group_level(subject.level_admin)
}

# Services with mqtt.system scope can publish/subscribe to system topics
allow if {
	startswith(input.resource.id, "celine/system/")
	subject.is_service
	subject.has_scope("mqtt.system")
}

# =============================================================================
# TWIN TOPICS
# =============================================================================

# Users can subscribe to twin telemetry if they have viewer+ access
allow if {
	input.action.name == "subscribe"
	topic_match(input.resource.id, "celine/twins/+/telemetry")
	subject.is_user
	subject.has_group_level(subject.level_viewer)
}

# Users can subscribe to twin status
allow if {
	input.action.name == "subscribe"
	topic_match(input.resource.id, "celine/twins/+/status")
	subject.is_user
	subject.has_group_level(subject.level_viewer)
}

# Editors+ can publish commands to twins
allow if {
	input.action.name == "publish"
	topic_match(input.resource.id, "celine/twins/+/commands")
	subject.is_user
	subject.has_group_level(subject.level_editor)
}

# Services with twin.write scope can publish to twin topics
allow if {
	input.action.name == "publish"
	topic_match(input.resource.id, "celine/twins/+/#")
	subject.is_service
	subject.has_any_scope(["twin.write", "twin.admin"])
}

# Services with twin.read scope can subscribe to twin topics
allow if {
	input.action.name == "subscribe"
	topic_match(input.resource.id, "celine/twins/+/#")
	subject.is_service
	subject.has_any_scope(["twin.read", "twin.write", "twin.admin"])
}

# =============================================================================
# PIPELINE TOPICS
# =============================================================================

# Anyone authenticated can subscribe to pipeline status
allow if {
	input.action.name == "subscribe"
	topic_match(input.resource.id, "celine/pipelines/+/status")
	not subject.is_anonymous
}

# Services with pipeline.execute can publish pipeline events
allow if {
	input.action.name == "publish"
	topic_match(input.resource.id, "celine/pipelines/+/#")
	subject.is_service
	subject.has_any_scope(["pipeline.execute", "pipeline.admin"])
}

# =============================================================================
# DATASET TOPICS
# =============================================================================

# Users can subscribe to dataset update notifications
allow if {
	input.action.name == "subscribe"
	topic_match(input.resource.id, "celine/datasets/+/updates")
	subject.is_user
	subject.has_group_level(subject.level_viewer)
}

# Services with dataset scope can publish dataset events
allow if {
	input.action.name == "publish"
	topic_match(input.resource.id, "celine/datasets/+/#")
	subject.is_service
	subject.has_any_scope(["dataset.admin"])
}

# =============================================================================
# USER-SPECIFIC TOPICS
# =============================================================================

# Users can subscribe/publish to their own topics
allow if {
	topic_parts := split(input.resource.id, "/")
	count(topic_parts) >= 3
	topic_parts[0] == "celine"
	topic_parts[1] == "users"
	topic_parts[2] == subject.subject_id
}

# =============================================================================
# WILDCARD SUBSCRIPTIONS
# =============================================================================

# Only admins can subscribe to broad wildcards
allow if {
	input.action.name == "subscribe"
	contains(input.resource.id, "#")
	subject.is_user
	subject.has_group_level(subject.level_admin)
}

allow if {
	input.action.name == "subscribe"
	contains(input.resource.id, "#")
	subject.is_service
	subject.has_scope("mqtt.admin")
}

# =============================================================================
# TOPIC MATCHING HELPERS
# =============================================================================

# Match topic against pattern with + and # wildcards
# + matches exactly one level
# # matches zero or more levels (only at end)
topic_match(topic, pattern) if {
	topic_parts := split(topic, "/")
	pattern_parts := split(pattern, "/")
	parts_match(topic_parts, pattern_parts)
}

# Base case: both empty
parts_match([], []) := true

# # wildcard matches everything remaining
parts_match(_, pattern_parts) if {
	count(pattern_parts) > 0
	pattern_parts[0] == "#"
}

# + wildcard matches exactly one segment
parts_match(topic_parts, pattern_parts) if {
	count(topic_parts) > 0
	count(pattern_parts) > 0
	pattern_parts[0] == "+"
	parts_match(array.slice(topic_parts, 1, count(topic_parts)), array.slice(pattern_parts, 1, count(pattern_parts)))
}

# Exact segment match
parts_match(topic_parts, pattern_parts) if {
	count(topic_parts) > 0
	count(pattern_parts) > 0
	topic_parts[0] == pattern_parts[0]
	parts_match(array.slice(topic_parts, 1, count(topic_parts)), array.slice(pattern_parts, 1, count(pattern_parts)))
}

# =============================================================================
# REASONS
# =============================================================================

reason := "topic access granted" if {
	allow
}

reason := "anonymous access denied" if {
	not allow
	subject.is_anonymous
}

reason := "topic access denied - insufficient privileges" if {
	not allow
	not subject.is_anonymous
}

# =============================================================================
# SUPERUSER CHECK
# =============================================================================

# Superuser bypasses all ACL checks
superuser if {
	subject.is_user
	subject.has_group_level(subject.level_admin)
}

superuser if {
	subject.is_service
	subject.has_scope("mqtt.admin")
}
