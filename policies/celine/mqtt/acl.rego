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

# Backward compatibility for /mqtt/superuser (if you still evaluate this path)
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
# - group_permissions: {group: ["read","write",...]}
# - scope_permissions: {scope: ["read","write",...]}
#
# MQTT actions are "publish" and "subscribe" (and optionally "superuser")
# You should map these in roles.json permissions lists.
################################################################################

has_capability_for_action(act) if {
  # via group permissions
  some grp_name in input.subject.groups
  perms := data.celine.roles.group_permissions[grp_name]
  perms[_] == act
} else if {
  # via scope permissions
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
  # missing effect => allow by default
  not rule.effect
} else if {
  rule.effect == "allow"
}

# If rule.actions missing => treat as "*"
rule_actions_match(actions) if {
  actions == "*"
} else if {
  not actions
} else if {
  some act in actions
  act == input.action.name
}

# If rule.topics missing => treat as "*"
rule_topics_match(topics, topic) if {
  topics == "*"
} else if {
  not topics
} else if {
  some pat in topics
  topic_match(pat, topic)
}

# If rule.subjects missing => match any subject
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

subject_types_match(types) if {
  not types
} else if {
  types == "*"
} else if {
  some tval in types
  tval == input.subject.type
}

subject_ids_match(ids) if {
  not ids
} else if {
  ids == "*"
} else if {
  some idval in ids
  idval == input.subject.id
}

subject_groups_match(groups) if {
  not groups
} else if {
  groups == "*"
} else if {
  some gname in groups
  subject_has_group_name(gname)
}

subject_scopes_match(scopes) if {
  not scopes
} else if {
  scopes == "*"
} else if {
  some sp in scopes
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

# Supports exact scope and prefix wildcard like "mqtt.*"
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
#
# - '+' matches exactly one level (no '/')
# - '#' matches multi-level suffix
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
  # Convert MQTT pattern to glob:
  #   '+' -> '*'
  #   '# ' is only valid at end; we already handled '/#' and '#'
  glob_pat := mqtt_to_glob(pattern)
  glob.match(glob_pat, ["/"], topic)
}

mqtt_to_glob(pat) := out if {
  # replace '+' with '*' for single-segment match
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
