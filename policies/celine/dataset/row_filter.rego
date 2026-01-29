# METADATA
# title: Dataset Row Filter Policy
# description: Generates row-level access predicates based on subject
# scope: package
# entrypoint: true
package celine.dataset.row_filter

import rego.v1

import data.celine.common.subject

# Default: no filters (full access if allowed)
default filters := []

# Default allow (row filters are additive to access policy)
default allow := true

# =============================================================================
# ORGANIZATION-BASED FILTERING
# =============================================================================

# Filter by organization if subject has org claim
filters contains filter if {
	subject.is_user
	org_id := input.subject.claims.organization
	org_id != null
	filter := {
		"field": "organization_id",
		"operator": "eq",
		"value": org_id,
	}
}

# Services may have org scope that limits access
filters contains filter if {
	subject.is_service
	org_id := input.subject.claims.organization
	org_id != null
	filter := {
		"field": "organization_id",
		"operator": "eq",
		"value": org_id,
	}
}

# =============================================================================
# CLASSIFICATION-BASED FILTERING
# =============================================================================

# Viewers can only see public classifications
filters contains filter if {
	input.resource.attributes.access_level == "internal"
	subject.is_user
	subject.in_group("viewers")
	not subject.in_any_group(["editors", "managers", "admins"])
	filter := {
		"field": "classification",
		"operator": "eq",
		"value": "public",
	}
}

# Editors can see public and internal classifications
filters contains filter if {
	input.resource.attributes.access_level == "internal"
	subject.is_user
	subject.in_group("editors")
	not subject.in_any_group(["managers", "admins"])
	filter := {
		"field": "classification",
		"operator": "in",
		"value": ["public", "internal"],
	}
}

# Managers and admins have no classification filter (full access)
# No filter rule needed - absence of filter means no restriction

# =============================================================================
# TIME-BASED FILTERING (EXAMPLE)
# =============================================================================

# Non-admins can only access data from last 2 years
# filters contains filter if {
#     subject.is_user
#     not subject.in_group("admins")
#     filter := {
#         "field": "created_at",
#         "operator": "gte",
#         "value": "2024-01-01T00:00:00Z"
#     }
# }

# =============================================================================
# HELPERS
# =============================================================================

# Expose allowed classifications for debugging/audit
allowed_classifications := ["public", "internal", "confidential"] if {
	subject.is_user
	subject.in_any_group(["managers", "admins"])
}

allowed_classifications := ["public", "internal"] if {
	subject.is_user
	subject.in_group("editors")
	not subject.in_any_group(["managers", "admins"])
}

allowed_classifications := ["public"] if {
	subject.is_user
	subject.in_group("viewers")
	not subject.in_any_group(["editors", "managers", "admins"])
}

allowed_classifications := ["public", "internal", "confidential"] if {
	subject.is_service
	subject.has_scope("dataset.admin")
}

allowed_classifications := ["public", "internal"] if {
	subject.is_service
	subject.has_scope("dataset.query")
	not subject.has_scope("dataset.admin")
}
