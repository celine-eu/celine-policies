# METADATA
# title: User Data Access Policy
# description: Controls access to user's own data and delegated resources
# scope: package
# entrypoint: true
package celine.userdata.access

import rego.v1

import data.celine.common.subject

# Default deny
default allow := false

default reason := ""

# =============================================================================
# OWN DATA ACCESS
# =============================================================================

# Users can always read their own data
allow if {
	input.resource.type == "userdata"
	input.action.name == "read"
	subject.is_user
	is_owner
}

reason := "user accessing own data" if {
	input.resource.type == "userdata"
	input.action.name == "read"
	subject.is_user
	is_owner
}

# Users can write/update their own data
allow if {
	input.resource.type == "userdata"
	input.action.name == "write"
	subject.is_user
	is_owner
}

reason := "user modifying own data" if {
	input.resource.type == "userdata"
	input.action.name == "write"
	subject.is_user
	is_owner
}

# Users can delete their own data
allow if {
	input.resource.type == "userdata"
	input.action.name == "delete"
	subject.is_user
	is_owner
}

reason := "user deleting own data" if {
	input.resource.type == "userdata"
	input.action.name == "delete"
	subject.is_user
	is_owner
}

# =============================================================================
# OWNERSHIP CHECK
# =============================================================================

is_owner if {
	input.resource.attributes.owner_id == input.subject.id
}

# =============================================================================
# SHARING / DELEGATION
# =============================================================================

# Users can share their own resources
allow if {
	input.resource.type == "userdata"
	input.action.name == "share"
	subject.is_user
	is_owner
}

reason := "owner can share resource" if {
	input.resource.type == "userdata"
	input.action.name == "share"
	subject.is_user
	is_owner
}

# Users can access shared resources
allow if {
	input.resource.type == "userdata"
	input.action.name == "read"
	subject.is_user
	is_shared_with_user
}

reason := "resource shared with user" if {
	input.resource.type == "userdata"
	input.action.name == "read"
	subject.is_user
	is_shared_with_user
}

# Check if resource is shared with current user
is_shared_with_user if {
	shared_with := input.resource.attributes.shared_with
	input.subject.id in shared_with
}

# Check if resource is shared with user's group
is_shared_with_user if {
	shared_with_groups := input.resource.attributes.shared_with_groups
	some group in input.subject.groups
	group in shared_with_groups
}

# =============================================================================
# DASHBOARD-SPECIFIC RULES
# =============================================================================

# Users can read their own dashboards
allow if {
	input.resource.type == "userdata"
	input.resource.attributes.resource_type == "dashboard"
	input.action.name == "read"
	subject.is_user
	is_owner
}

# Users can read public dashboards
allow if {
	input.resource.type == "userdata"
	input.resource.attributes.resource_type == "dashboard"
	input.resource.attributes.visibility == "public"
	input.action.name == "read"
	subject.is_user
}

reason := "public dashboard readable" if {
	input.resource.type == "userdata"
	input.resource.attributes.resource_type == "dashboard"
	input.resource.attributes.visibility == "public"
	input.action.name == "read"
	subject.is_user
}

# =============================================================================
# ADMIN OVERRIDE
# =============================================================================

# Admins can access any user data (for support/auditing)
allow if {
	input.resource.type == "userdata"
	input.action.name in {"read", "write", "delete"}
	subject.is_user
	subject.has_group_level(subject.level_admin)
}

reason := "admin override" if {
	input.resource.type == "userdata"
	subject.is_user
	subject.has_group_level(subject.level_admin)
	allow
}

# =============================================================================
# SERVICE ACCESS
# =============================================================================

# Services with userdata.read scope can read user data
allow if {
	input.resource.type == "userdata"
	input.action.name == "read"
	subject.is_service
	subject.has_any_scope(["userdata.read", "userdata.admin"])
}

# Services with userdata.admin scope can modify user data
allow if {
	input.resource.type == "userdata"
	input.action.name in {"write", "delete"}
	subject.is_service
	subject.has_scope("userdata.admin")
}

reason := "service access granted" if {
	input.resource.type == "userdata"
	subject.is_service
	allow
}

# =============================================================================
# DENIAL REASONS
# =============================================================================

reason := "not resource owner" if {
	not allow
	subject.is_user
	not is_owner
	not is_shared_with_user
	not subject.has_group_level(subject.level_admin)
}

reason := "anonymous access denied" if {
	not allow
	subject.is_anonymous
}

reason := "insufficient service scope" if {
	not allow
	subject.is_service
}
