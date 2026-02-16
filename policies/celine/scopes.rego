package celine.scopes

default deny = true

is_service if {
  input.subject.type == "service"
}

is_user if {
  input.subject.type == "user"
}

has_scope(required) if {
  some i
  input.subject.scopes[i] == required
}

has_scope_service_admin(service) if {
  has_scope(sprintf("%s.admin", [service]))
}

has_scope_resource_wildcard(service, resource) if {
  has_scope(sprintf("%s.%s.*", [service, resource]))
}

service_allowed(required, service, resource) if {
  is_service
  has_scope(required)
}

service_allowed(required, service, resource) if {
  is_service
  has_scope_service_admin(service)
}

service_allowed(required, service, resource) if {
  is_service
  has_scope_resource_wildcard(service, resource)
}

# ---- user groups ----

user_in_group(g) if {
  some i
  input.subject.groups[i] == g
}

user_is_admin if {
  is_user
  user_in_group("admin")
}

user_is_admin if {
  is_user
  user_in_group("mqtt.admin")
}

user_is_service_admin(service) if {
  is_user
  user_in_group(sprintf("%s.admin", [service]))
}

user_is_service_admin(service) if {
  is_user
  user_in_group(sprintf("mqtt:%s:admin", [service]))
}

# required is "<service>.<resource>.<verb>" (e.g. pipelines.runs.read)
user_allowed(required, service, resource, verb) if {
  is_user
  user_in_group(required)
}

# Alternative group naming: "mqtt:<service>:<resource>:<verb>"
user_allowed(required, service, resource, verb) if {
  is_user
  user_in_group(sprintf("mqtt:%s:%s:%s", [service, resource, verb]))
}

# Resource wildcard groups: "<service>.<resource>.*" or "mqtt:<service>:<resource>:*"
user_allowed(required, service, resource, verb) if {
  is_user
  user_in_group(sprintf("%s.%s.*", [service, resource]))
}

user_allowed(required, service, resource, verb) if {
  is_user
  user_in_group(sprintf("mqtt:%s:%s:*", [service, resource]))
}

# Admin groups
user_allowed(required, service, resource, verb) if {
  user_is_admin
}

user_allowed(required, service, resource, verb) if {
  user_is_service_admin(service)
}
