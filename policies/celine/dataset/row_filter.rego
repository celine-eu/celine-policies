# METADATA
# title: Dataset Row Filter Policy
# description: Generates row-level access predicates based on subject
# scope: package
# entrypoint: true
package celine.dataset.row_filter

import rego.v1

import data.celine.common.subject

default filters := []
default allow := true

full_classifications := {"public", "internal", "confidential"}

# =============================================================================
# FILTER ACCUMULATOR
# =============================================================================

filter_set contains filter if {
	not subject.is_anonymous
	org_id := input.subject.claims.organization
	org_id != null
	filter := {
		"field": "organization_id",
		"operator": "eq",
		"value": org_id,
	}
}

filter_set contains filter if {
	input.resource.attributes.access_level == "internal"
	needs_classification_filter
	allowed := allowed_classifications
	filter := {
		"field": "classification",
		"operator": "in",
		"value": allowed,
	}
}

needs_classification_filter if {
	allowed := allowed_classifications_set
	count(allowed) < count(full_classifications)
}

# =============================================================================
# MATERIALIZE FILTERS AS LIST
# =============================================================================

filters := [f | f := filter_set[_]]

# =============================================================================
# CLASSIFICATION DERIVATION (group hierarchy ∩ client scopes)
# =============================================================================

allowed_classifications := [c | c := allowed_classifications_set[_]]

allowed_classifications_set := {c |
	c := group_allowed_set[_]
	c in scope_allowed_set
}

group_allowed_set := {"public", "internal", "confidential"} if {
	subject.is_user
	subject.has_group_level(subject.level_manager)
} else := {"public", "internal"} if {
	subject.is_user
	subject.has_group_level(subject.level_editor)
} else := {"public"} if {
	subject.is_user
	subject.has_group_level(subject.level_viewer)
} else := {"public", "internal", "confidential"} if {
	subject.is_service
} else := {"public"}

scope_allowed_set := {"public", "internal", "confidential"} if {
	subject.has_scope("dataset.admin")
} else := {"public", "internal"} if {
	subject.has_scope("dataset.query")
	not subject.has_scope("dataset.admin")
} else := {"public"}
