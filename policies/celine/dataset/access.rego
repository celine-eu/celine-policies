# METADATA
# title: Dataset Access Policy
# description: Controls access to datasets based on access level and subject type
# scope: package
# entrypoint: true
package celine.dataset.access

import rego.v1

import data.celine.common.access_levels
import data.celine.common.subject

# Default deny
default allow := false

# Default empty reason
default reason := ""

# =============================================================================
# OPEN DATASETS
# =============================================================================

# Anyone can read open datasets (including anonymous)
allow if {
	input.resource.attributes.access_level == "open"
	input.action.name == "read"
}

reason := "open datasets are publicly readable" if {
	input.resource.attributes.access_level == "open"
	input.action.name == "read"
}

# =============================================================================
# INTERNAL DATASETS - Users
# =============================================================================

# Users in viewers+ groups can read internal datasets
allow if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "read"
	subject.is_user
	subject.has_group_level(subject.level_viewer)
}

reason := "user has viewer access to internal datasets" if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "read"
	subject.is_user
	subject.has_group_level(subject.level_viewer)
}

# Users in editors+ groups can write internal datasets
allow if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "write"
	subject.is_user
	subject.has_group_level(subject.level_editor)
}

reason := "user has editor access to internal datasets" if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "write"
	subject.is_user
	subject.has_group_level(subject.level_editor)
}

# =============================================================================
# INTERNAL DATASETS - Services
# =============================================================================

# Services with dataset.query scope can read internal datasets
allow if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "read"
	subject.is_service
	subject.has_scope("dataset.query")
}

reason := "service has dataset.query scope" if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "read"
	subject.is_service
	subject.has_scope("dataset.query")
}

# Services with dataset.admin scope can write internal datasets
allow if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "write"
	subject.is_service
	subject.has_scope("dataset.admin")
}

reason := "service has dataset.admin scope" if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "write"
	subject.is_service
	subject.has_scope("dataset.admin")
}

# =============================================================================
# RESTRICTED DATASETS - Users
# =============================================================================

# Only admins can read restricted datasets
allow if {
	input.resource.attributes.access_level == "restricted"
	input.action.name == "read"
	subject.is_user
	subject.has_group_level(subject.level_admin)
}

reason := "user has admin access to restricted datasets" if {
	input.resource.attributes.access_level == "restricted"
	input.action.name == "read"
	subject.is_user
	subject.has_group_level(subject.level_admin)
}

# Only admins can write restricted datasets
allow if {
	input.resource.attributes.access_level == "restricted"
	input.action.name == "write"
	subject.is_user
	subject.has_group_level(subject.level_admin)
}

reason := "user has admin access to restricted datasets" if {
	input.resource.attributes.access_level == "restricted"
	input.action.name == "write"
	subject.is_user
	subject.has_group_level(subject.level_admin)
}

# =============================================================================
# RESTRICTED DATASETS - Services
# =============================================================================

# Only services with dataset.admin scope can access restricted datasets
allow if {
	input.resource.attributes.access_level == "restricted"
	input.action.name in {"read", "write"}
	subject.is_service
	subject.has_scope("dataset.admin")
}

reason := "service has dataset.admin scope for restricted access" if {
	input.resource.attributes.access_level == "restricted"
	input.action.name in {"read", "write"}
	subject.is_service
	subject.has_scope("dataset.admin")
}

# =============================================================================
# ADMIN ACTIONS
# =============================================================================

# Admin action requires admin group or dataset.admin scope
allow if {
	input.action.name == "admin"
	subject.is_user
	subject.has_group_level(subject.level_admin)
}

allow if {
	input.action.name == "admin"
	subject.is_service
	subject.has_scope("dataset.admin")
}

reason := "admin action authorized" if {
	input.action.name == "admin"
	allow
}

# =============================================================================
# DENIAL REASONS
# =============================================================================

reason := "anonymous access denied for non-open datasets" if {
	not allow
	subject.is_anonymous
	input.resource.attributes.access_level != "open"
}

reason := "insufficient group privileges" if {
	not allow
	subject.is_user
	not subject.is_anonymous
}

reason := "insufficient scope privileges" if {
	not allow
	subject.is_service
}
