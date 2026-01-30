package celine.mqtt.acl_test

import rego.v1
import data.celine.mqtt.acl as policy

# IMPORTANT: do NOT name this test_roles / test_* or it will be executed as a test.
roles_fixture := {
  "group_permissions": {
    "admins":  ["publish", "subscribe", "superuser"],
    "viewers": ["subscribe"]
  },
  "scope_permissions": {
    "mqtt.admin": ["publish", "subscribe", "superuser"],
    "mqtt.read":  ["subscribe"],
    "mqtt.write": ["publish"]
  }
}

test_allow_publish_for_admin_group if {
  rules := [
    {
      "actions": ["publish"],
      "topics":  ["celine/#"],
      "subjects": { "groups": ["admins"] }
    }
  ]

  inp := {
    "subject": {
      "id": "u-1",
      "type": "user",
      "groups": ["admins"],
      "scopes": [],
      "claims": {}
    },
    "resource": { "type": "topic", "id": "celine/x/y", "attributes": {"clientid":"cid"} },
    "action": { "name": "publish", "context": {} },
    "environment": {}
  }

  policy.allow
    with input as inp
    with data.celine.mqtt.acl.rules as rules
    with data.celine.roles as roles_fixture
}

test_deny_publish_for_non_admin if {
  rules := [
    {
      "actions": ["publish"],
      "topics":  ["celine/#"],
      "subjects": { "groups": ["admins"] }
    }
  ]

  inp := {
    "subject": {
      "id": "u-2",
      "type": "user",
      "groups": ["viewers"],
      "scopes": [],
      "claims": {}
    },
    "resource": { "type": "topic", "id": "celine/x/y", "attributes": {"clientid":"cid"} },
    "action": { "name": "publish", "context": {} },
    "environment": {}
  }

  not policy.allow
    with input as inp
    with data.celine.mqtt.acl.rules as rules
    with data.celine.roles as roles_fixture
}

test_allow_subscribe_with_scope_wildcard if {
  rules := [
    {
      "actions": ["subscribe"],
      "topics":  ["celine/telemetry/+"],
      "subjects": { "scopes": ["mqtt.*"] }
    }
  ]

  inp := {
    "subject": {
      "id": "svc-1",
      "type": "service",
      "groups": [],
      "scopes": ["mqtt.read", "other.scope"],
      "claims": {}
    },
    "resource": { "type": "topic", "id": "celine/telemetry/node42", "attributes": {"clientid":"svc"} },
    "action": { "name": "subscribe", "context": {} },
    "environment": {}
  }

  policy.allow
    with input as inp
    with data.celine.mqtt.acl.rules as rules
    with data.celine.roles as roles_fixture
}

test_hash_wildcard_matches_root_prefix if {
  rules := [
    {
      "actions": ["subscribe"],
      "topics":  ["celine/#"],
      "subjects": { "types": ["service"] }
    }
  ]

  inp := {
    "subject": {
      "id": "svc-2",
      "type": "service",
      "groups": [],
      "scopes": ["mqtt.read"],
      "claims": {}
    },
    "resource": { "type": "topic", "id": "celine", "attributes": {"clientid":"svc"} },
    "action": { "name": "subscribe", "context": {} },
    "environment": {}
  }

  policy.allow
    with input as inp
    with data.celine.mqtt.acl.rules as rules
    with data.celine.roles as roles_fixture
}
