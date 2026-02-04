package celine.mqtt_test

import rego.v1

import data.celine.mqtt

# =============================================================================
# TOPIC PARSING
# =============================================================================

test_parse_topic_full if {
    result := mqtt.parse_topic("celine/dt/simulation/123")
    result.service == "dt"
    result.resource == "simulation"
}

test_parse_topic_pipeline if {
    result := mqtt.parse_topic("celine/pipeline/status/job-456")
    result.service == "pipeline"
    result.resource == "status"
}

# =============================================================================
# SCOPE DERIVATION
# =============================================================================

test_required_scope_subscribe if {
    mqtt.required_scope("celine/dt/simulation/123", "subscribe") == "dt.simulation.read"
}

test_required_scope_publish if {
    mqtt.required_scope("celine/dt/simulation/123", "publish") == "dt.simulation.write"
}

test_required_scope_read if {
    mqtt.required_scope("celine/pipeline/status/job-1", "read") == "pipeline.status.read"
}

# =============================================================================
# AUTHORIZATION
# =============================================================================

test_allow_subscribe if {
    mqtt.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dt.simulation.read"]},
        "resource": {"type": "topic", "id": "celine/dt/simulation/123"},
        "action": {"name": "subscribe"},
    }
}

test_allow_publish if {
    mqtt.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dt.simulation.write"]},
        "resource": {"type": "topic", "id": "celine/dt/simulation/123"},
        "action": {"name": "publish"},
    }
}

test_allow_via_admin if {
    mqtt.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dt.admin"]},
        "resource": {"type": "topic", "id": "celine/dt/values/sensor-1"},
        "action": {"name": "publish"},
    }
}

test_deny_cross_service if {
    not mqtt.allow with input as {
        "subject": {"type": "service", "id": "svc-pipelines", "scopes": ["pipeline.status.read"]},
        "resource": {"type": "topic", "id": "celine/dt/simulation/123"},
        "action": {"name": "subscribe"},
    }
}

test_deny_wrong_action if {
    not mqtt.allow with input as {
        "subject": {"type": "service", "id": "svc-dt", "scopes": ["dt.simulation.read"]},
        "resource": {"type": "topic", "id": "celine/dt/simulation/123"},
        "action": {"name": "publish"},
    }
}

test_deny_anonymous if {
    not mqtt.allow with input as {
        "subject": null,
        "resource": {"type": "topic", "id": "celine/dt/simulation/123"},
        "action": {"name": "subscribe"},
    }
}

# =============================================================================
# PIPELINE
# =============================================================================

test_pipeline_subscribe if {
    mqtt.allow with input as {
        "subject": {"type": "service", "id": "svc-pipelines", "scopes": ["pipeline.status.read"]},
        "resource": {"type": "topic", "id": "celine/pipeline/status/job-123"},
        "action": {"name": "subscribe"},
    }
}

test_pipeline_publish if {
    mqtt.allow with input as {
        "subject": {"type": "service", "id": "svc-pipelines", "scopes": ["pipeline.status.write"]},
        "resource": {"type": "topic", "id": "celine/pipeline/status/job-123"},
        "action": {"name": "publish"},
    }
}
