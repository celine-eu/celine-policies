package celine.authz_test

import rego.v1

import data.celine.authz

# =============================================================================
# SCOPE DERIVATION TESTS
# =============================================================================

test_derived_scope_full_path if {
    authz.derived_scope == "dt.simulation.read" with input as {
        "resource": {
            "type": "dt",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "read"},
    }
}

test_derived_scope_fallback_no_resource_type if {
    authz.derived_scope == "dataset.query" with input as {
        "resource": {
            "type": "dataset",
            "attributes": {},
        },
        "action": {"name": "query"},
    }
}

test_derived_scope_fallback_empty_resource_type if {
    authz.derived_scope == "dataset.query" with input as {
        "resource": {
            "type": "dataset",
            "attributes": {"resource_type": ""},
        },
        "action": {"name": "query"},
    }
}

test_derived_scope_pipeline_status if {
    authz.derived_scope == "pipeline.status.write" with input as {
        "resource": {
            "type": "pipeline",
            "attributes": {"resource_type": "status"},
        },
        "action": {"name": "write"},
    }
}

# =============================================================================
# DIGITAL TWIN AUTHORIZATION
# =============================================================================

test_dt_simulation_read if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.simulation.read"],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "read"},
    }
}

test_dt_simulation_write if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.simulation.write"],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "write"},
    }
}

test_dt_simulation_run if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.simulation.run"],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "run"},
    }
}

test_dt_values_read if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.values.read"],
        },
        "resource": {
            "type": "dt",
            "id": "twin-456",
            "attributes": {"resource_type": "values"},
        },
        "action": {"name": "read"},
    }
}

test_dt_app_run if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.app.run"],
        },
        "resource": {
            "type": "dt",
            "id": "app-789",
            "attributes": {"resource_type": "app"},
        },
        "action": {"name": "run"},
    }
}

# =============================================================================
# PIPELINE AUTHORIZATION
# =============================================================================

test_pipeline_status_read if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-pipelines",
            "scopes": ["pipeline.status.read"],
        },
        "resource": {
            "type": "pipeline",
            "id": "job-123",
            "attributes": {"resource_type": "status"},
        },
        "action": {"name": "read"},
    }
}

test_pipeline_status_write if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-pipelines",
            "scopes": ["pipeline.status.write"],
        },
        "resource": {
            "type": "pipeline",
            "id": "job-123",
            "attributes": {"resource_type": "status"},
        },
        "action": {"name": "write"},
    }
}

test_pipeline_job_execute if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-pipelines",
            "scopes": ["pipeline.job.execute"],
        },
        "resource": {
            "type": "pipeline",
            "id": "job-456",
            "attributes": {"resource_type": "job"},
        },
        "action": {"name": "execute"},
    }
}

# =============================================================================
# DATASET AUTHORIZATION
# =============================================================================

test_dataset_query if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-dataset",
            "scopes": ["dataset.query"],
        },
        "resource": {
            "type": "dataset",
            "id": "ds-123",
            "attributes": {},
        },
        "action": {"name": "query"},
    }
}

test_dataset_read if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-dataset",
            "scopes": ["dataset.read"],
        },
        "resource": {
            "type": "dataset",
            "id": "ds-123",
            "attributes": {},
        },
        "action": {"name": "read"},
    }
}

test_dataset_write if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-dataset",
            "scopes": ["dataset.write"],
        },
        "resource": {
            "type": "dataset",
            "id": "ds-123",
            "attributes": {},
        },
        "action": {"name": "write"},
    }
}

# =============================================================================
# ADMIN SCOPE TESTS
# =============================================================================

test_dt_admin_allows_simulation_read if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.admin"],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "read"},
    }
}

test_dt_admin_allows_values_write if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.admin"],
        },
        "resource": {
            "type": "dt",
            "id": "twin-456",
            "attributes": {"resource_type": "values"},
        },
        "action": {"name": "write"},
    }
}

test_pipeline_admin_allows_status_write if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-pipelines",
            "scopes": ["pipeline.admin"],
        },
        "resource": {
            "type": "pipeline",
            "id": "job-123",
            "attributes": {"resource_type": "status"},
        },
        "action": {"name": "write"},
    }
}

test_dataset_admin_allows_query if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-dataset",
            "scopes": ["dataset.admin"],
        },
        "resource": {
            "type": "dataset",
            "id": "ds-123",
            "attributes": {},
        },
        "action": {"name": "query"},
    }
}

# =============================================================================
# WILDCARD SCOPE TESTS
# =============================================================================

test_dt_simulation_wildcard_allows_read if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.simulation.*"],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "read"},
    }
}

test_dt_simulation_wildcard_allows_run if {
    authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.simulation.*"],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "run"},
    }
}

test_wildcard_does_not_cross_resources if {
    not authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.simulation.*"],
        },
        "resource": {
            "type": "dt",
            "id": "twin-456",
            "attributes": {"resource_type": "values"},
        },
        "action": {"name": "read"},
    }
}

# =============================================================================
# DENIAL TESTS
# =============================================================================

test_deny_anonymous if {
    not authz.allow with input as {
        "subject": null,
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "read"},
    }
}

test_deny_missing_scope if {
    not authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.values.read"],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "read"},
    }
}

test_deny_cross_service if {
    not authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-pipelines",
            "scopes": ["pipeline.status.read"],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "read"},
    }
}

test_deny_wrong_action if {
    not authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-digital-twin",
            "scopes": ["dt.simulation.read"],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "write"},
    }
}

test_deny_empty_scopes if {
    not authz.allow with input as {
        "subject": {
            "type": "service",
            "id": "svc-unknown",
            "scopes": [],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "read"},
    }
}

# =============================================================================
# REASON TESTS
# =============================================================================

test_reason_authorized if {
    authz.reason == "authorized" with input as {
        "subject": {
            "type": "service",
            "id": "svc-dt",
            "scopes": ["dt.simulation.read"],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "read"},
    }
}

test_reason_anonymous if {
    authz.reason == "anonymous access denied" with input as {
        "subject": null,
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "read"},
    }
}

test_reason_missing_scope if {
    authz.reason == "missing required scope" with input as {
        "subject": {
            "type": "service",
            "id": "svc-dt",
            "scopes": ["other.scope"],
        },
        "resource": {
            "type": "dt",
            "id": "sim-123",
            "attributes": {"resource_type": "simulation"},
        },
        "action": {"name": "read"},
    }
}
