# METADATA
# title: Pipeline State Transition Policy
# description: Validates pipeline state transitions and authorization
# scope: package
# entrypoint: true
package celine.pipeline.state

import rego.v1

import data.celine.common.subject

default allow := false
default reason := ""

valid_transitions := {
	"pending": {"started", "cancelled"},
	"started": {"running", "failed", "cancelled"},
	"running": {"completed", "failed", "cancelled"},
	"completed": set(),
	"failed": {"pending"},
	"cancelled": {"pending"},
}

is_valid_transition if {
	from_state := input.action.context.from_state
	to_state := input.action.context.to_state
	allowed_targets := valid_transitions[from_state]
	to_state in allowed_targets
}

# =============================================================================
# AUTHORIZATION RULES
# =============================================================================

allow if {
	input.resource.type == "pipeline"
	input.action.name == "transition"
	is_valid_transition
	subject.is_user
	subject.has_any_scope(["pipeline.execute", "pipeline.admin"])
	can_user_transition
}

allow if {
	input.resource.type == "pipeline"
	input.action.name == "transition"
	is_valid_transition
	subject.is_service
	can_service_transition
}

# =============================================================================
# USER TRANSITION PERMISSIONS (group hierarchy)
# =============================================================================

can_user_transition if {
	subject.has_group_level(subject.level_editor)
	input.action.context.to_state in {"started", "running"}
}

can_user_transition if {
	subject.has_group_level(subject.level_manager)
	input.action.context.to_state in {"started", "running", "cancelled", "pending"}
}

can_user_transition if {
	subject.has_group_level(subject.level_admin)
}

# =============================================================================
# SERVICE TRANSITION PERMISSIONS (scopes only)
# =============================================================================

can_service_transition if {
	subject.has_scope("pipeline.execute")
	input.action.context.to_state in {"started", "running", "completed", "failed"}
} else if {
	subject.has_scope("pipeline.admin")
}

# =============================================================================
# READ ACCESS
# =============================================================================

allow if {
	input.resource.type == "pipeline"
	input.action.name == "read"
	not subject.is_anonymous
}

reason := "authenticated users can read pipeline state" if {
	input.resource.type == "pipeline"
	input.action.name == "read"
	not subject.is_anonymous
}

# =============================================================================
# REASONS
# =============================================================================

reason := "valid state transition authorized" if {
	allow
	input.action.name == "transition"
}

reason := "invalid state transition" if {
	not allow
	input.action.name == "transition"
	not is_valid_transition
}

reason := "missing pipeline scope for requesting client" if {
	not allow
	input.action.name == "transition"
	is_valid_transition
	subject.is_user
	not subject.has_any_scope(["pipeline.execute", "pipeline.admin"])
}

reason := "insufficient privileges for transition" if {
	not allow
	input.action.name == "transition"
	is_valid_transition
	subject.is_user
	subject.has_any_scope(["pipeline.execute", "pipeline.admin"])
	not can_user_transition
}

reason := "insufficient scope for transition" if {
	not allow
	input.action.name == "transition"
	is_valid_transition
	subject.is_service
	not can_service_transition
}

valid_target_states := targets if {
	from_state := input.action.context.from_state
	targets := valid_transitions[from_state]
}

all_states := {"pending", "started", "running", "completed", "failed", "cancelled"}
