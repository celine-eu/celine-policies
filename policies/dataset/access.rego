package celine.dataset.access

default allow = false

# -------------------------------------------------
# OPEN — evaluated without subject
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

has_scope(s) if {
  has_subject
  input.subject.scopes[_] == s
}

has_role(r) if {
  has_subject
  input.subject.roles[_] == r
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

allow if {
  input.dataset.access_level == "internal"
  is_service
  has_scope("dataset.query")
}

allow if {
  input.dataset.access_level == "internal"
  is_human
  has_role("manager")
}

allow if {
  input.dataset.access_level == "internal"
  is_human
  has_role("operator")
}

# -------------------------------------------------
# RESTRICTED
# -------------------------------------------------

allow if {
  input.dataset.access_level == "restricted"
  is_service
  has_scope("dataset.admin")
}

allow if {
  input.dataset.access_level == "restricted"
  is_human
  has_role("admin")
}
