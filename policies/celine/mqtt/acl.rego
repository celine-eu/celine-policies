package celine.mqtt.acl

import data.celine.scopes

default allow = false
default reason = "denied"

parts := split(input.resource.id, "/")

is_celine_prefix if {
  count(parts) >= 2
  parts[0] == "celine"
}

service := parts[1]

resource := parts[2]

# ---- action -> verb ----

valid_action if { input.action.name == "subscribe" }
valid_action if { input.action.name == "read" }
valid_action if { input.action.name == "publish" }

verb := "read" if { input.action.name == "subscribe" }
verb := "read" if { input.action.name == "read" }
verb := "write" if { input.action.name == "publish" }

required := sprintf("%s.%s.%s", [service, resource, verb])

# ---- topic shapes ----

# "celine/<service>"
is_service_only if {
  is_celine_prefix
  count(parts) == 2
}

# "celine/<service>/#" or "celine/<service>/+"
is_service_level_wildcard if {
  is_celine_prefix
  count(parts) == 3
  (parts[2] == "#" or parts[2] == "+")
}

# "celine/<service>/<resource>/..." (resource cannot be "#" or "+")
is_valid_topic_format if {
  is_celine_prefix
  count(parts) >= 3
  not is_service_level_wildcard
  not (resource == "#" or resource == "+")
}

# ---- allow rules (all require valid_action) ----

allow if {
  valid_action
  is_service_only
  scopes.has_scope_service_admin(service)
  reason = "service admin scope"
}

allow if {
  valid_action
  is_service_only
  scopes.user_is_admin
  reason = "user global admin"
}

allow if {
  valid_action
  is_service_only
  scopes.user_is_service_admin(service)
  reason = "user service admin"
}

allow if {
  valid_action
  is_service_level_wildcard
  scopes.has_scope_service_admin(service)
  reason = "service admin wildcard"
}

allow if {
  valid_action
  is_service_level_wildcard
  scopes.user_is_admin
  reason = "user global admin wildcard"
}

allow if {
  valid_action
  is_service_level_wildcard
  scopes.user_is_service_admin(service)
  reason = "user service admin wildcard"
}

allow if {
  valid_action
  is_valid_topic_format
  scopes.service_allowed(required, service, resource)
  reason = "service scope"
}

allow if {
  valid_action
  is_valid_topic_format
  scopes.user_allowed(required, service, resource, verb)
  reason = "user group"
}

# ---- denial reasons (mutually exclusive) ----

reason = "invalid action" if {
  not valid_action
}

reason = "invalid topic format" if {
  valid_action
  is_celine_prefix
  not is_valid_topic_format
  not is_service_only
  not is_service_level_wildcard
}

reason = "service-level wildcard denied" if {
  valid_action
  is_service_level_wildcard
  not scopes.has_scope_service_admin(service)
  not scopes.user_is_admin
  not scopes.user_is_service_admin(service)
}
