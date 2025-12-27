package celine.dataset.access

default allow = false

# -------------------------------------------------
# OPEN — anonymous allowed
# -------------------------------------------------

allow if {
  input.dataset.access_level == "open"
}

# -------------------------------------------------
# Guards
# -------------------------------------------------

has_subject if {
  input.subject != null
}

has_scope(scope) if {
  has_subject
  input.subject.scopes[_] == scope
}

has_group(group) if {
  has_subject
  input.subject.groups[_] == group
}

is_service if {
  has_subject
  count(input.subject.scopes) > 0
}

is_human if {
  has_subject
  not is_service
}

# -------------------------------------------------
# INTERNAL
# -------------------------------------------------

# Services with query capability
allow if {
  input.dataset.access_level == "internal"
  is_service
  has_scope("dataset.query")
}

# Humans: operators, managers, admins
allow if {
  input.dataset.access_level == "internal"
  is_human
  has_group("operators")
}

allow if {
  input.dataset.access_level == "internal"
  is_human
  has_group("managers")
}

allow if {
  input.dataset.access_level == "internal"
  is_human
  has_group("admins")
}

# -------------------------------------------------
# RESTRICTED
# -------------------------------------------------

# Services with admin capability
allow if {
  input.dataset.access_level == "restricted"
  is_service
  has_scope("dataset.admin")
}

# Humans: admins only
allow if {
  input.dataset.access_level == "restricted"
  is_human
  has_group("admins")
}
