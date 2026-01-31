# METADATA
# title: Dataset Access Policy
# description: Controls access to datasets based on access level and subject type
# scope: package
# entrypoint: true
package celine.dataset.access

import rego.v1

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
# INTERNAL DATASETS
# =============================================================================

# Users (viewers+) can read internal datasets if the calling client has dataset.query (or admin)
allow if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "read"
	subject.is_user
	subject.has_group_level(subject.level_viewer)
	subject.has_any_scope(["dataset.query", "dataset.admin"])
}

reason := "user has viewer access and client has dataset.query scope" if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "read"
	subject.is_user
	subject.has_group_level(subject.level_viewer)
	subject.has_any_scope(["dataset.query", "dataset.admin"])
}

# Users (editors+) can write internal datasets if the calling client has dataset.admin
allow if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "write"
	subject.is_user
	subject.has_group_level(subject.level_editor)
	subject.has_scope("dataset.admin")
}

reason := "user has editor access and client has dataset.admin scope" if {
	input.resource.attributes.access_level == "internal"
	input.action.name == "write"
	subject.is_user
	subject.has_group_level(subject.level_editor)
	subject.has_scope("dataset.admin")
}

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
# RESTRICTED DATASETS
# =============================================================================

# Only admins can read/write restricted datasets and the calling client must have dataset.admin
allow if {
	input.resource.attributes.access_level == "restricted"
	input.action.name in {"read", "write"}
	subject.is_user
	subject.has_group_level(subject.level_admin)
	subject.has_scope("dataset.admin")
}

reason := "user has admin access and client has dataset.admin scope" if {
	input.resource.attributes.access_level == "restricted"
	input.action.name in {"read", "write"}
	subject.is_user
	subject.has_group_level(subject.level_admin)
	subject.has_scope("dataset.admin")
}

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

# Admin action requires admin group and dataset.admin scope (users) or dataset.admin scope (services)
allow if {
	input.action.name == "admin"
	subject.is_user
	subject.has_group_level(subject.level_admin)
	subject.has_scope("dataset.admin")
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

reason := "missing dataset scope for requesting client" if {
	not allow
	not subject.is_anonymous
	subject.is_user
	input.resource.attributes.access_level != "open"
	not subject.has_any_scope(["dataset.query", "dataset.admin"])
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
