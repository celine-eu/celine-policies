# METADATA
# title: Digital Twin Access and Event Policy
# description: Controls access to digital twins and event generation
# scope: package
# entrypoint: true
package celine.twin.access

import rego.v1

import data.celine.common.subject

# Default deny
default allow := false

default reason := ""

# =============================================================================
# READ ACCESS
# =============================================================================

# Any authenticated user can read twin data
allow if {
	input.resource.type == "twin"
	input.action.name == "read"
	subject.is_user
	subject.has_group_level(subject.level_viewer)
}

reason := "user can read twin data" if {
	input.resource.type == "twin"
	input.action.name == "read"
	subject.is_user
	subject.has_group_level(subject.level_viewer)
}

# Services with twin.read scope can read
allow if {
	input.resource.type == "twin"
	input.action.name == "read"
	subject.is_service
	subject.has_any_scope(["twin.read", "twin.write", "twin.admin"])
}

reason := "service has twin read scope" if {
	input.resource.type == "twin"
	input.action.name == "read"
	subject.is_service
	subject.has_any_scope(["twin.read", "twin.write", "twin.admin"])
}

# =============================================================================
# WRITE ACCESS
# =============================================================================

# Editors+ can write twin configuration
allow if {
	input.resource.type == "twin"
	input.action.name == "write"
	subject.is_user
	subject.has_group_level(subject.level_editor)
}

reason := "user can write twin data" if {
	input.resource.type == "twin"
	input.action.name == "write"
	subject.is_user
	subject.has_group_level(subject.level_editor)
}

# Services with twin.write scope can write
allow if {
	input.resource.type == "twin"
	input.action.name == "write"
	subject.is_service
	subject.has_any_scope(["twin.write", "twin.admin"])
}

reason := "service has twin write scope" if {
	input.resource.type == "twin"
	input.action.name == "write"
	subject.is_service
	subject.has_any_scope(["twin.write", "twin.admin"])
}

# =============================================================================
# SIMULATE ACCESS
# =============================================================================

# Managers+ can run simulations
allow if {
	input.resource.type == "twin"
	input.action.name == "simulate"
	subject.is_user
	subject.has_group_level(subject.level_manager)
}

reason := "user can run simulations" if {
	input.resource.type == "twin"
	input.action.name == "simulate"
	subject.is_user
	subject.has_group_level(subject.level_manager)
}

# Services with twin.simulate scope can simulate
allow if {
	input.resource.type == "twin"
	input.action.name == "simulate"
	subject.is_service
	subject.has_any_scope(["twin.simulate", "twin.admin"])
}

reason := "service has twin simulate scope" if {
	input.resource.type == "twin"
	input.action.name == "simulate"
	subject.is_service
	subject.has_any_scope(["twin.simulate", "twin.admin"])
}

# =============================================================================
# ADMIN ACCESS
# =============================================================================

# Only admins can administer twins
allow if {
	input.resource.type == "twin"
	input.action.name == "admin"
	subject.is_user
	subject.has_group_level(subject.level_admin)
}

allow if {
	input.resource.type == "twin"
	input.action.name == "admin"
	subject.is_service
	subject.has_scope("twin.admin")
}

reason := "admin access granted" if {
	input.resource.type == "twin"
	input.action.name == "admin"
	allow
}

# =============================================================================
# EVENT EMISSION
# =============================================================================

# Services can emit events if they have appropriate scope
allow if {
	input.resource.type == "twin"
	input.action.name == "emit_event"
	subject.is_service
	can_emit_event
}

can_emit_event if {
	subject.has_any_scope(["twin.write", "twin.simulate", "twin.admin"])
}

# Event type restrictions could be added here
# e.g., only simulation services can emit simulation events
can_emit_event if {
	input.action.context.event_type == "simulation"
	subject.has_scope("twin.simulate")
}

reason := "service can emit twin events" if {
	input.resource.type == "twin"
	input.action.name == "emit_event"
	subject.is_service
	can_emit_event
}

# =============================================================================
# DENIAL REASONS
# =============================================================================

reason := "anonymous access denied" if {
	not allow
	subject.is_anonymous
}

reason := "insufficient privileges" if {
	not allow
	not subject.is_anonymous
}
