# METADATA
# title: Dataset Access Policy Tests
# scope: package
package celine.dataset.access_test

import rego.v1

import data.celine.dataset.access

# =============================================================================
# OPEN DATASET TESTS
# =============================================================================

test_open_dataset_anonymous_read_allowed if {
	access.allow with input as {
		"subject": null,
		"resource": {
			"type": "dataset",
			"id": "ds-public",
			"attributes": {"access_level": "open"},
		},
		"action": {"name": "read", "context": {}},
	}
}

test_open_dataset_user_read_allowed if {
	access.allow with input as {
		"subject": {
			"id": "user-1",
			"type": "user",
			"groups": ["viewers"],
			"scopes": [],
			"claims": {},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-public",
			"attributes": {"access_level": "open"},
		},
		"action": {"name": "read", "context": {}},
	}
}

# =============================================================================
# INTERNAL DATASET TESTS - Users
# =============================================================================

test_internal_dataset_viewer_read_allowed if {
	access.allow with input as {
		"subject": {
			"id": "user-1",
			"type": "user",
			"groups": ["viewers"],
			"scopes": [],
			"claims": {},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-internal",
			"attributes": {"access_level": "internal"},
		},
		"action": {"name": "read", "context": {}},
	}
}

test_internal_dataset_viewer_write_denied if {
	not access.allow with input as {
		"subject": {
			"id": "user-1",
			"type": "user",
			"groups": ["viewers"],
			"scopes": [],
			"claims": {},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-internal",
			"attributes": {"access_level": "internal"},
		},
		"action": {"name": "write", "context": {}},
	}
}

test_internal_dataset_editor_write_allowed if {
	access.allow with input as {
		"subject": {
			"id": "user-1",
			"type": "user",
			"groups": ["editors"],
			"scopes": [],
			"claims": {},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-internal",
			"attributes": {"access_level": "internal"},
		},
		"action": {"name": "write", "context": {}},
	}
}

test_internal_dataset_anonymous_denied if {
	not access.allow with input as {
		"subject": null,
		"resource": {
			"type": "dataset",
			"id": "ds-internal",
			"attributes": {"access_level": "internal"},
		},
		"action": {"name": "read", "context": {}},
	}
}

# =============================================================================
# INTERNAL DATASET TESTS - Services
# =============================================================================

test_internal_dataset_service_query_scope_read_allowed if {
	access.allow with input as {
		"subject": {
			"id": "svc-forecast",
			"type": "service",
			"groups": [],
			"scopes": ["dataset.query"],
			"claims": {"client_id": "svc-forecast"},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-internal",
			"attributes": {"access_level": "internal"},
		},
		"action": {"name": "read", "context": {}},
	}
}

test_internal_dataset_service_query_scope_write_denied if {
	not access.allow with input as {
		"subject": {
			"id": "svc-forecast",
			"type": "service",
			"groups": [],
			"scopes": ["dataset.query"],
			"claims": {"client_id": "svc-forecast"},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-internal",
			"attributes": {"access_level": "internal"},
		},
		"action": {"name": "write", "context": {}},
	}
}

test_internal_dataset_service_admin_scope_write_allowed if {
	access.allow with input as {
		"subject": {
			"id": "svc-admin",
			"type": "service",
			"groups": [],
			"scopes": ["dataset.admin"],
			"claims": {"client_id": "svc-admin"},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-internal",
			"attributes": {"access_level": "internal"},
		},
		"action": {"name": "write", "context": {}},
	}
}

# =============================================================================
# RESTRICTED DATASET TESTS - Users
# =============================================================================

test_restricted_dataset_viewer_denied if {
	not access.allow with input as {
		"subject": {
			"id": "user-1",
			"type": "user",
			"groups": ["viewers"],
			"scopes": [],
			"claims": {},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-restricted",
			"attributes": {"access_level": "restricted"},
		},
		"action": {"name": "read", "context": {}},
	}
}

test_restricted_dataset_manager_denied if {
	not access.allow with input as {
		"subject": {
			"id": "user-1",
			"type": "user",
			"groups": ["managers"],
			"scopes": [],
			"claims": {},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-restricted",
			"attributes": {"access_level": "restricted"},
		},
		"action": {"name": "read", "context": {}},
	}
}

test_restricted_dataset_admin_read_allowed if {
	access.allow with input as {
		"subject": {
			"id": "user-1",
			"type": "user",
			"groups": ["admins"],
			"scopes": [],
			"claims": {},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-restricted",
			"attributes": {"access_level": "restricted"},
		},
		"action": {"name": "read", "context": {}},
	}
}

test_restricted_dataset_admin_write_allowed if {
	access.allow with input as {
		"subject": {
			"id": "user-1",
			"type": "user",
			"groups": ["admins"],
			"scopes": [],
			"claims": {},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-restricted",
			"attributes": {"access_level": "restricted"},
		},
		"action": {"name": "write", "context": {}},
	}
}

# =============================================================================
# RESTRICTED DATASET TESTS - Services
# =============================================================================

test_restricted_dataset_service_query_scope_denied if {
	not access.allow with input as {
		"subject": {
			"id": "svc-forecast",
			"type": "service",
			"groups": [],
			"scopes": ["dataset.query"],
			"claims": {"client_id": "svc-forecast"},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-restricted",
			"attributes": {"access_level": "restricted"},
		},
		"action": {"name": "read", "context": {}},
	}
}

test_restricted_dataset_service_admin_scope_allowed if {
	access.allow with input as {
		"subject": {
			"id": "svc-admin",
			"type": "service",
			"groups": [],
			"scopes": ["dataset.admin"],
			"claims": {"client_id": "svc-admin"},
		},
		"resource": {
			"type": "dataset",
			"id": "ds-restricted",
			"attributes": {"access_level": "restricted"},
		},
		"action": {"name": "read", "context": {}},
	}
}
