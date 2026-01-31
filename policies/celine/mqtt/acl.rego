package celine.mqtt.acl

import rego.v1

default allow := false
default reason := "no matching allow rule"
default superuser := false

################################################################################
# Entry points (FastAPI PolicyEngine contract)
################################################################################

allow if {
  input.subject != null
  input.resource.type == "topic"
  has_capability_for_action(input.action.name)
  matches_any_acl_rule(input.resource.id)
}

reason := msg if {
  not allow
  msg := deny_reason
}

# Backward compatibility for /mqtt/superuser
superuser if {
  subject_has_group_name("admins")
} else if {
  subject_has_scope_pattern("mqtt.admin")
} else if {
  input.action.name == "superuser"
  allow
}

################################################################################
# Capability layer (roles.json)
#
# roles.json must be mounted at data.celine.roles
# - group_permissions: {group: ["read","publish","subscribe","superuser",...]}
# - scope_permissions: {scope: ["read","publish","subscribe","superuser",...]}
#
# MQTT actions:
# - subscribe  (MOSQ_ACL_SUBSCRIBE)
# - read       (MOSQ_ACL_READ)
# - publish    (MOSQ_ACL_WRITE)
# - superuser  (optional)
################################################################################

has_capability_for_action(act) if {
  some grp_name in input.subject.groups
  perms := data.celine.roles.group_permissions[grp_name]
  perms[_] == act
} else if {
  some scope_name in input.subject.scopes
  perms := data.celine.roles.scope_permissions[scope_name]
  perms[_] == act
}

################################################################################
# ACL layer (topic scoping)
#
# data.celine.mqtt.acl.rules: list of rule objects
################################################################################

matches_any_acl_rule(topic) if {
  some rule in data.celine.mqtt.acl.rules
  acl_rule_matches(rule, topic)
}

acl_rule_matches(rule, topic) if {
  rule_subjects_match(rule.subjects)
  rule_topics_match(rule.topics, topic)
  rule_actions_match(rule.actions)
  rule_effect_allows(rule)
}

rule_effect_allows(rule) if {
  not rule.effect
} else if {
  rule.effect == "allow"
}

rule_actions_match(actions) if {
  actions == "*"
} else if {
  not actions
} else if {
  some act in actions
  act == input.action.name
}

rule_topics_match(topics, topic) if {
  topics == "*"
} else if {
  not topics
} else if {
  some pat in topics
  topic_match(pat, topic)
}

rule_subjects_match(subjects) if {
  not subjects
} else if {
  subject_types_match(subjects)
  subject_ids_match(subjects)
  subject_groups_match(subjects)
  subject_scopes_match(subjects)
}

subject_types_match(subjects) if {
  not subjects.types
} else if {
  subjects.types == "*"
} else if {
  some tval in subjects.types
  tval == input.subject.type
}

subject_ids_match(subjects) if {
  not subjects.ids
} else if {
  subjects.ids == "*"
} else if {
  some idval in subjects.ids
  idval == input.subject.id
}

subject_groups_match(subjects) if {
  not subjects.groups
} else if {
  subjects.groups == "*"
} else if {
  some gname in subjects.groups
  subject_has_group_name(gname)
}

subject_scopes_match(subjects) if {
  not subjects.scopes
} else if {
  subjects.scopes == "*"
} else if {
  some sp in subjects.scopes
  subject_has_scope_pattern(sp)
}

################################################################################
# Subject helpers
################################################################################

subject_has_group_name(gname) if {
  input.subject != null
  some sg in input.subject.groups
  sg == gname
}

subject_has_scope_pattern(pattern) if {
  input.subject != null
  some have in input.subject.scopes
  scope_pattern_match(pattern, have)
}

scope_pattern_match(pattern, have) if {
  pattern == have
} else if {
  endswith(pattern, ".*")
  prefix := trim_suffix(pattern, ".*")
  startswith(have, sprintf("%s.", [prefix]))
}

################################################################################
# Topic matching (MQTT wildcards # and +) - Rego v1 compatible using glob.match
################################################################################

topic_match(pattern, topic) if {
  pattern == topic
} else if {
  pattern == "#"
} else if {
  endswith(pattern, "/#")
  prefix := trim_suffix(pattern, "/#")
  topic == prefix
} else if {
  endswith(pattern, "/#")
  prefix := trim_suffix(pattern, "/#")
  startswith(topic, sprintf("%s/", [prefix]))
} else if {
  glob_pat := mqtt_to_glob(pattern)
  glob.match(glob_pat, ["/"], topic)
}

mqtt_to_glob(pat) := out if {
  out := replace(pat, "+", "*")
}

################################################################################
# Deny reason (best-effort)
################################################################################

deny_reason := msg if {
  input.subject == null
  msg := "anonymous subject not allowed"
} else if {
  input.resource.type != "topic"
  msg := "resource type must be topic"
} else if {
  msg := "no ACL rule matched or capability missing"
}
