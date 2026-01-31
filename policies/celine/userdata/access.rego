# METADATA
# title: User Data Access Policy
# description: Controls access to user's own data and delegated resources
# scope: package
# entrypoint: true
package celine.userdata.access

import rego.v1

import data.celine.common.subject

default allow := false
default reason := ""

# =============================================================================
# OWN DATA ACCESS (user ownership ∩ client scopes)
# =============================================================================

allow if {
	input.resource.type == "userdata"
	input.action.name == "read"
	subject.is_user
	is_owner
	subject.has_any_scope(["userdata.read", "userdata.write", "userdata.admin"])
}

reason := "user accessing own data" if {
	input.resource.type == "userdata"
	input.action.name == "read"
	subject.is_user
	is_owner
	subject.has_any_scope(["userdata.read", "userdata.write", "userdata.admin"])
}

allow if {
	input.resource.type == "userdata"
	input.action.name == "write"
	subject.is_user
	is_owner
	subject.has_any_scope(["userdata.write", "userdata.admin"])
}

reason := "user modifying own data" if {
	input.resource.type == "userdata"
	input.action.name == "write"
	subject.is_user
	is_owner
	subject.has_any_scope(["userdata.write", "userdata.admin"])
}

allow if {
	input.resource.type == "userdata"
	input.action.name == "delete"
	subject.is_user
	is_owner
	subject.has_any_scope(["userdata.write", "userdata.admin"])
}

reason := "user deleting own data" if {
	input.resource.type == "userdata"
	input.action.name == "delete"
	subject.is_user
	is_owner
	subject.has_any_scope(["userdata.write", "userdata.admin"])
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

allow if {
	input.resource.type == "userdata"
	input.action.name == "share"
	subject.is_user
	is_owner
	subject.has_any_scope(["userdata.write", "userdata.admin"])
}

reason := "owner can share resource" if {
	input.resource.type == "userdata"
	input.action.name == "share"
	subject.is_user
	is_owner
	subject.has_any_scope(["userdata.write", "userdata.admin"])
}

allow if {
	input.resource.type == "userdata"
	input.action.name == "read"
	subject.is_user
	is_shared_with_user
	subject.has_any_scope(["userdata.read", "userdata.write", "userdata.admin"])
}

reason := "resource shared with user" if {
	input.resource.type == "userdata"
	input.action.name == "read"
	subject.is_user
	is_shared_with_user
	subject.has_any_scope(["userdata.read", "userdata.write", "userdata.admin"])
}

is_shared_with_user if {
	shared_with := input.resource.attributes.shared_with
	shared_with != null
	input.subject.id in shared_with
}

is_shared_with_user if {
	shared_with_groups := input.resource.attributes.shared_with_groups
	shared_with_groups != null
	some group in input.subject.groups
	group in shared_with_groups
}

# =============================================================================
# DASHBOARD-SPECIFIC RULES
# =============================================================================

allow if {
	input.resource.type == "userdata"
	input.resource.attributes.resource_type == "dashboard"
	input.action.name == "read"
	subject.is_user
	is_owner
	subject.has_any_scope(["userdata.read", "userdata.write", "userdata.admin"])
}

allow if {
	input.resource.type == "userdata"
	input.resource.attributes.resource_type == "dashboard"
	input.resource.attributes.visibility == "public"
	input.action.name == "read"
	subject.is_user
	subject.has_any_scope(["userdata.read", "userdata.write", "userdata.admin"])
}

reason := "public dashboard readable" if {
	input.resource.type == "userdata"
	input.resource.attributes.resource_type == "dashboard"
	input.resource.attributes.visibility == "public"
	input.action.name == "read"
	subject.is_user
	subject.has_any_scope(["userdata.read", "userdata.write", "userdata.admin"])
}

# =============================================================================
# ADMIN OVERRIDE
# =============================================================================

allow if {
	input.resource.type == "userdata"
	input.action.name in {"read", "write", "delete"}
	subject.is_user
	subject.has_group_level(subject.level_admin)
	subject.has_scope("userdata.admin")
}

reason := "admin override" if {
	input.resource.type == "userdata"
	subject.is_user
	subject.has_group_level(subject.level_admin)
	subject.has_scope("userdata.admin")
	allow
}

# =============================================================================
# SERVICE ACCESS
# =============================================================================

allow if {
	input.resource.type == "userdata"
	input.action.name == "read"
	subject.is_service
	subject.has_any_scope(["userdata.read", "userdata.admin"])
}

allow if {
	input.resource.type == "userdata"
	input.action.name == "write"
	subject.is_service
	subject.has_any_scope(["userdata.write", "userdata.admin"])
}

allow if {
	input.resource.type == "userdata"
	input.action.name == "delete"
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

reason := "missing userdata scope for requesting client" if {
	not allow
	subject.is_user
	not subject.is_anonymous
	not subject.has_any_scope(["userdata.read", "userdata.write", "userdata.admin"])
}

reason := "not resource owner" if {
	not allow
	subject.is_user
	subject.has_any_scope(["userdata.read", "userdata.write", "userdata.admin"])
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
