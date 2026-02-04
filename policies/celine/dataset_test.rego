package celine.dataset_test

import rego.v1

import data.celine.dataset

# =============================================================================
# OPEN DATASETS
# =============================================================================

test_open_query_no_scope if {
    dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-any", "scopes": []},
        "resource": {"type": "dataset", "id": "ds-public", "attributes": {"access_level": "open"}},
        "action": {"name": "query"},
    }
}

test_open_read_no_scope if {
    dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-any", "scopes": []},
        "resource": {"type": "dataset", "id": "ds-public", "attributes": {"access_level": "open"}},
        "action": {"name": "read"},
    }
}

test_open_write_needs_scope if {
    not dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-any", "scopes": []},
        "resource": {"type": "dataset", "id": "ds-public", "attributes": {"access_level": "open"}},
        "action": {"name": "write"},
    }
}

test_open_write_with_scope if {
    dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-any", "scopes": ["dataset.write"]},
        "resource": {"type": "dataset", "id": "ds-public", "attributes": {"access_level": "open"}},
        "action": {"name": "write"},
    }
}

test_open_reason if {
    dataset.reason == "open dataset - public access" with input as {
        "subject": {"type": "service", "id": "svc-any", "scopes": []},
        "resource": {"type": "dataset", "id": "ds-public", "attributes": {"access_level": "open"}},
        "action": {"name": "query"},
    }
}

# =============================================================================
# RESTRICTED DATASETS
# =============================================================================

test_restricted_denied_without_admin if {
    not dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-any", "scopes": ["dataset.query", "dataset.read"]},
        "resource": {"type": "dataset", "id": "ds-secret", "attributes": {"access_level": "restricted"}},
        "action": {"name": "query"},
    }
}

test_restricted_allowed_with_admin if {
    dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-admin", "scopes": ["dataset.admin"]},
        "resource": {"type": "dataset", "id": "ds-secret", "attributes": {"access_level": "restricted"}},
        "action": {"name": "query"},
    }
}

test_restricted_reason if {
    dataset.reason == "restricted dataset requires admin scope" with input as {
        "subject": {"type": "service", "id": "svc-any", "scopes": ["dataset.query"]},
        "resource": {"type": "dataset", "id": "ds-secret", "attributes": {"access_level": "restricted"}},
        "action": {"name": "query"},
    }
}

# =============================================================================
# INTERNAL DATASETS (default)
# =============================================================================

test_internal_query if {
    dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dataset.query"]},
        "resource": {"type": "dataset", "id": "ds-123", "attributes": {}},
        "action": {"name": "query"},
    }
}

test_internal_read if {
    dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dataset.read"]},
        "resource": {"type": "dataset", "id": "ds-123", "attributes": {}},
        "action": {"name": "read"},
    }
}

test_internal_write if {
    dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dataset.write"]},
        "resource": {"type": "dataset", "id": "ds-123", "attributes": {}},
        "action": {"name": "write"},
    }
}

test_internal_denied_wrong_scope if {
    not dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dataset.read"]},
        "resource": {"type": "dataset", "id": "ds-123", "attributes": {}},
        "action": {"name": "write"},
    }
}

test_internal_admin_allows_all if {
    dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-admin", "scopes": ["dataset.admin"]},
        "resource": {"type": "dataset", "id": "ds-123", "attributes": {}},
        "action": {"name": "query"},
    }
}

test_internal_explicit if {
    dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dataset.query"]},
        "resource": {"type": "dataset", "id": "ds-123", "attributes": {"access_level": "internal"}},
        "action": {"name": "query"},
    }
}

# =============================================================================
# ADMIN ACTIONS
# =============================================================================

test_create_needs_admin if {
    dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-admin", "scopes": ["dataset.admin"]},
        "resource": {"type": "dataset", "id": "ds-new", "attributes": {}},
        "action": {"name": "create"},
    }
}

test_delete_needs_admin if {
    dataset.allow with input as {
        "subject": {"type": "service", "id": "svc-admin", "scopes": ["dataset.admin"]},
        "resource": {"type": "dataset", "id": "ds-123", "attributes": {}},
        "action": {"name": "delete"},
    }
}

# =============================================================================
# ANONYMOUS
# =============================================================================

test_anonymous_denied if {
    not dataset.allow with input as {
        "subject": null,
        "resource": {"type": "dataset", "id": "ds-123", "attributes": {}},
        "action": {"name": "query"},
    }
}

test_anonymous_reason if {
    dataset.reason == "anonymous access denied" with input as {
        "subject": null,
        "resource": {"type": "dataset", "id": "ds-123", "attributes": {}},
        "action": {"name": "query"},
    }
}
