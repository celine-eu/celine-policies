# METADATA
# title: Pipeline State Transition Policy
# description: Validates pipeline state transitions and authorization
# scope: package
# entrypoint: true
package celine.pipeline.state

import rego.v1

import data.celine.common.subject

# Default deny
default allow := false

default reason := ""

# =============================================================================
# VALID STATE TRANSITIONS
# =============================================================================

# Define valid state machine transitions
valid_transitions := {
	"pending": {"started", "cancelled"},
	"started": {"running", "failed", "cancelled"},
	"running": {"completed", "failed", "cancelled"},
	"completed": set(),
	"failed": {"pending"}, # Allow retry
	"cancelled": {"pending"}, # Allow restart
}

# Check if transition is valid in state machine
is_valid_transition if {
	from_state := input.action.context.from_state
	to_state := input.action.context.to_state
	allowed_targets := valid_transitions[from_state]
	to_state in allowed_targets
}

# =============================================================================
# AUTHORIZATION RULES
# =============================================================================

# Users can trigger transitions if they have appropriate group level
allow if {
	input.resource.type == "pipeline"
	input.action.name == "transition"
	is_valid_transition
	subject.is_user
	can_user_transition
}

# Services can trigger transitions if they have pipeline scope
allow if {
	input.resource.type == "pipeline"
	input.action.name == "transition"
	is_valid_transition
	subject.is_service
	can_service_transition
}

# =============================================================================
# USER TRANSITION PERMISSIONS
# =============================================================================

# Viewers cannot trigger any transitions
# Editors can start and view
can_user_transition if {
	subject.in_group("editors")
	input.action.context.to_state in {"started", "running"}
}

# Managers can also cancel and retry
can_user_transition if {
	subject.in_group("managers")
	input.action.context.to_state in {"started", "running", "cancelled", "pending"}
}

# Admins can do everything including marking complete/failed
can_user_transition if {
	subject.in_group("admins")
}

# =============================================================================
# SERVICE TRANSITION PERMISSIONS
# =============================================================================

# Services with pipeline.execute can trigger execution transitions
can_service_transition if {
	subject.has_scope("pipeline.execute")
	input.action.context.to_state in {"started", "running", "completed", "failed"}
}

# Services with pipeline.admin can do everything
can_service_transition if {
	subject.has_scope("pipeline.admin")
}

# =============================================================================
# READ ACCESS
# =============================================================================

# Anyone authenticated can read pipeline state
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

reason := "insufficient privileges for transition" if {
	not allow
	input.action.name == "transition"
	is_valid_transition
	subject.is_user
	not can_user_transition
}

reason := "insufficient scope for transition" if {
	not allow
	input.action.name == "transition"
	is_valid_transition
	subject.is_service
	not can_service_transition
}

# =============================================================================
# HELPERS FOR CONSUMERS
# =============================================================================

# List all valid target states from current state
valid_target_states := targets if {
	from_state := input.action.context.from_state
	targets := valid_transitions[from_state]
}

# Get all states
all_states := {"pending", "started", "running", "completed", "failed", "cancelled"}
