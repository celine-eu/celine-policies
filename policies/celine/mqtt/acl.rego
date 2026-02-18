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
  parts[2] == "#"
}

is_service_level_wildcard if {
  is_celine_prefix
  count(parts) == 3
  parts[2] == "+"
}

# "celine/<service>/<resource>/..." (resource cannot be "#" or "+")
is_valid_topic_format if {
  is_celine_prefix
  count(parts) >= 3
  not is_service_level_wildcard
  resource != "#"
  resource != "+"
}


# ---- allow rules ----

allow if {
  valid_action
  is_service_only
  data.celine.scopes.has_scope_service_admin(service)
}

allow if {
  valid_action
  is_service_only
  data.celine.scopes.user_is_admin
}

allow if {
  valid_action
  is_service_only
  data.celine.scopes.user_is_service_admin(service)
}

allow if {
  valid_action
  is_service_level_wildcard
  data.celine.scopes.has_scope_service_admin(service)
}

allow if {
  valid_action
  is_service_level_wildcard
  data.celine.scopes.user_is_admin
}

allow if {
  valid_action
  is_service_level_wildcard
  data.celine.scopes.user_is_service_admin(service)
}

allow if {
  valid_action
  is_valid_topic_format
  data.celine.scopes.service_allowed(required, service, resource)
}

allow if {
  valid_action
  is_valid_topic_format
  data.celine.scopes.user_allowed(required, service, resource, verb)
}


# ---- reason rules (separate from allow, using same conditions) ----

reason = "service admin scope" if {
  valid_action
  is_service_only
  data.celine.scopes.has_scope_service_admin(service)
}

reason = "user global admin" if {
  valid_action
  is_service_only
  data.celine.scopes.user_is_admin
}

reason = "user service admin" if {
  valid_action
  is_service_only
  data.celine.scopes.user_is_service_admin(service)
}

reason = "service admin wildcard" if {
  valid_action
  is_service_level_wildcard
  data.celine.scopes.has_scope_service_admin(service)
}

reason = "user global admin wildcard" if {
  valid_action
  is_service_level_wildcard
  data.celine.scopes.user_is_admin
}

reason = "user service admin wildcard" if {
  valid_action
  is_service_level_wildcard
  data.celine.scopes.user_is_service_admin(service)
}

reason = "service scope" if {
  valid_action
  is_valid_topic_format
  data.celine.scopes.service_allowed(required, service, resource)
}

reason = "user group" if {
  valid_action
  is_valid_topic_format
  data.celine.scopes.user_allowed(required, service, resource, verb)
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
  not data.celine.scopes.has_scope_service_admin(service)
  not data.celine.scopes.user_is_admin
  not data.celine.scopes.user_is_service_admin(service)
}
