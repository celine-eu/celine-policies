package celine.scopes

# Grants on the broker come from a service account's scopes, and from nothing else
# (REQ-0014, ADR-0012). A person's token is a user and holds no MQTT grant: no group of
# either level reaches this policy (the backend sends none), and no realm role is an MQTT
# grant. The groups a user token used to be judged by (`admin`, `mqtt.admin`,
# `<service>.admin`, `<service>.<resource>.<verb>`, `mqtt:<service>:...`) were read from a
# merge of realm and organization groups, so an organization could name one of its groups
# like a broker grant and hold it.

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
  is_service
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
