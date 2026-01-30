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
# FILTER ACCUMULATOR
# =============================================================================

# Collect filters in a set, then expose them as a list via `filters`
filter_set contains filter if {
    # ORGANIZATION-BASED FILTERING (user)
    subject.is_user
    org_id := input.subject.claims.organization
    org_id != null
    filter := {
        "field": "organization_id",
        "operator": "eq",
        "value": org_id,
    }
}

filter_set contains filter if {
    # ORGANIZATION-BASED FILTERING (service)
    subject.is_service
    org_id := input.subject.claims.organization
    org_id != null
    filter := {
        "field": "organization_id",
        "operator": "eq",
        "value": org_id,
    }
}

filter_set contains filter if {
    # CLASSIFICATION-BASED FILTERING (viewers)
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

filter_set contains filter if {
    # CLASSIFICATION-BASED FILTERING (editors)
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

# Managers/admins: no classification filter

# =============================================================================
# MATERIALIZE FILTERS AS LIST
# =============================================================================

filters := [f | f := filter_set[_]]

# =============================================================================
# HELPERS
# =============================================================================

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
