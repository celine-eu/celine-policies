# METADATA
# title: MQTT ACL Policy Tests
# scope: package
package celine.mqtt.acl_test

import rego.v1

import data.celine.mqtt.acl

roles_fixture := {
	"group_permissions": {
		"viewers": ["subscribe", "read"],
		"editors": ["subscribe", "read", "publish"],
		"admins": ["subscribe", "read", "publish", "superuser"],
	},
	"scope_permissions": {
		"mqtt.read": ["subscribe", "read"],
		"mqtt.write": ["publish"],
		"mqtt.admin": ["subscribe", "read", "publish", "superuser"],
	},
}

acl_fixture := {
	"rules": [
		{
			"subjects": {"types": ["user"], "groups": ["viewers"]},
			"topics": ["celine/telemetry/+/readings"],
			"actions": ["subscribe", "read"],
			"effect": "allow",
		},
		{
			"subjects": {"types": ["service"], "scopes": ["mqtt.write"]},
			"topics": ["celine/telemetry/#"],
			"actions": ["publish"],
			"effect": "allow",
		},
		{
			"subjects": {"groups": ["admins"]},
			"topics": ["#"],
			"actions": "*",
			"effect": "allow",
		},
	],
}

test_allow_viewer_subscribe_specific_topic if {
	acl.allow with input as {
		"subject": {"id": "u1", "type": "user", "groups": ["viewers"], "scopes": [], "claims": {}},
		"resource": {"type": "topic", "id": "celine/telemetry/device1/readings", "attributes": {}},
		"action": {"name": "subscribe", "context": {}},
	} with data.celine.roles as roles_fixture with data.celine.mqtt.acl as acl_fixture
}

test_allow_viewer_read_specific_topic if {
	acl.allow with input as {
		"subject": {"id": "u1", "type": "user", "groups": ["viewers"], "scopes": [], "claims": {}},
		"resource": {"type": "topic", "id": "celine/telemetry/device1/readings", "attributes": {}},
		"action": {"name": "read", "context": {}},
	} with data.celine.roles as roles_fixture with data.celine.mqtt.acl as acl_fixture
}

test_deny_viewer_publish if {
	not acl.allow with input as {
		"subject": {"id": "u1", "type": "user", "groups": ["viewers"], "scopes": [], "claims": {}},
		"resource": {"type": "topic", "id": "celine/telemetry/device1/readings", "attributes": {}},
		"action": {"name": "publish", "context": {}},
	} with data.celine.roles as roles_fixture with data.celine.mqtt.acl as acl_fixture
}

test_allow_service_publish_with_scope if {
	acl.allow with input as {
		"subject": {"id": "s1", "type": "service", "groups": [], "scopes": ["mqtt.write"], "claims": {"client_id": "s1"}},
		"resource": {"type": "topic", "id": "celine/telemetry/device1/readings", "attributes": {}},
		"action": {"name": "publish", "context": {}},
	} with data.celine.roles as roles_fixture with data.celine.mqtt.acl as acl_fixture
}

test_deny_subscribe_to_hash_if_not_admin if {
	not acl.allow with input as {
		"subject": {"id": "u1", "type": "user", "groups": ["viewers"], "scopes": [], "claims": {}},
		"resource": {"type": "topic", "id": "#", "attributes": {}},
		"action": {"name": "subscribe", "context": {}},
	} with data.celine.roles as roles_fixture with data.celine.mqtt.acl as acl_fixture
}

test_allow_admin_subscribe_hash if {
	acl.allow with input as {
		"subject": {"id": "admin", "type": "user", "groups": ["admins"], "scopes": [], "claims": {}},
		"resource": {"type": "topic", "id": "#", "attributes": {}},
		"action": {"name": "subscribe", "context": {}},
	} with data.celine.roles as roles_fixture with data.celine.mqtt.acl as acl_fixture
}
