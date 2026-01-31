# METADATA
# title: Digital Twin Access and Event Policy
# description: Controls access to digital twins (dt) and event emission
# scope: package
# entrypoint: true
package celine.dt.access

import rego.v1

import data.celine.common.subject

default allow := false
default reason := ""

# =============================================================================
# READ ACCESS
# =============================================================================

allow if {
	input.resource.type == "dt"
	input.action.name == "read"
	subject.is_user
	subject.has_group_level(subject.level_viewer)
	subject.has_any_scope(["dt.read", "dt.write", "dt.admin"])
}

reason := "user can read dt data" if {
	input.resource.type == "dt"
	input.action.name == "read"
	subject.is_user
	subject.has_group_level(subject.level_viewer)
	subject.has_any_scope(["dt.read", "dt.write", "dt.admin"])
}

allow if {
	input.resource.type == "dt"
	input.action.name == "read"
	subject.is_service
	subject.has_any_scope(["dt.read", "dt.write", "dt.admin"])
}

reason := "service has dt read scope" if {
	input.resource.type == "dt"
	input.action.name == "read"
	subject.is_service
	subject.has_any_scope(["dt.read", "dt.write", "dt.admin"])
}

# =============================================================================
# WRITE ACCESS
# =============================================================================

allow if {
	input.resource.type == "dt"
	input.action.name == "write"
	subject.is_user
	subject.has_group_level(subject.level_editor)
	subject.has_any_scope(["dt.write", "dt.admin"])
}

reason := "user can write dt data" if {
	input.resource.type == "dt"
	input.action.name == "write"
	subject.is_user
	subject.has_group_level(subject.level_editor)
	subject.has_any_scope(["dt.write", "dt.admin"])
}

allow if {
	input.resource.type == "dt"
	input.action.name == "write"
	subject.is_service
	subject.has_any_scope(["dt.write", "dt.admin"])
}

reason := "service has dt write scope" if {
	input.resource.type == "dt"
	input.action.name == "write"
	subject.is_service
	subject.has_any_scope(["dt.write", "dt.admin"])
}

# =============================================================================
# SIMULATE ACCESS
# =============================================================================

allow if {
	input.resource.type == "dt"
	input.action.name == "simulate"
	subject.is_user
	subject.has_group_level(subject.level_manager)
	subject.has_any_scope(["dt.simulate", "dt.admin"])
}

reason := "user can run simulations" if {
	input.resource.type == "dt"
	input.action.name == "simulate"
	subject.is_user
	subject.has_group_level(subject.level_manager)
	subject.has_any_scope(["dt.simulate", "dt.admin"])
}

allow if {
	input.resource.type == "dt"
	input.action.name == "simulate"
	subject.is_service
	subject.has_any_scope(["dt.simulate", "dt.admin"])
}

reason := "service has dt simulate scope" if {
	input.resource.type == "dt"
	input.action.name == "simulate"
	subject.is_service
	subject.has_any_scope(["dt.simulate", "dt.admin"])
}

# =============================================================================
# ADMIN ACCESS
# =============================================================================

allow if {
	input.resource.type == "dt"
	input.action.name == "admin"
	subject.is_user
	subject.has_group_level(subject.level_admin)
	subject.has_scope("dt.admin")
}

allow if {
	input.resource.type == "dt"
	input.action.name == "admin"
	subject.is_service
	subject.has_scope("dt.admin")
}

reason := "admin access granted" if {
	input.resource.type == "dt"
	input.action.name == "admin"
	allow
}

# =============================================================================
# EVENT EMISSION
# =============================================================================

allow if {
	input.resource.type == "dt"
	input.action.name == "emit_event"
	subject.is_service
	can_emit_event
}

can_emit_event if {
	subject.has_any_scope(["dt.write", "dt.simulate", "dt.admin"])
}

can_emit_event if {
	input.action.context.event_type == "simulation"
	subject.has_any_scope(["dt.simulate", "dt.admin"])
}

reason := "service can emit dt events" if {
	input.resource.type == "dt"
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
