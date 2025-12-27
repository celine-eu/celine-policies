package celine.dataset.access_test

import data.celine.dataset.access.allow

# -------------------------------------------------
# OPEN
# -------------------------------------------------

test_open_allows_anonymous := true if {
  allow with input as {
    "dataset": {"access_level": "open"},
    "subject": null
  }
}

test_open_allows_service := true if {
  allow with input as {
    "dataset": {"access_level": "open"},
    "subject": {
      "scopes": ["dataset.query"],
      "roles": [],
      "groups": []
    }
  }
}

test_open_allows_human := true if {
  allow with input as {
    "dataset": {"access_level": "open"},
    "subject": {
      "scopes": [],
      "roles": ["viewer"],
      "groups": []
    }
  }
}

# -------------------------------------------------
# INTERNAL — services
# -------------------------------------------------

test_internal_service_with_query_scope := true if {
  allow with input as {
    "dataset": {"access_level": "internal"},
    "subject": {
      "scopes": ["dataset.query"],
      "roles": [],
      "groups": []
    }
  }
}

test_internal_service_without_query_scope_denied := true if {
  not allow with input as {
    "dataset": {"access_level": "internal"},
    "subject": {
      "scopes": ["dataset.read"],
      "roles": [],
      "groups": []
    }
  }
}

# -------------------------------------------------
# INTERNAL — humans
# -------------------------------------------------

test_internal_human_manager := true if {
  allow with input as {
    "dataset": {"access_level": "internal"},
    "subject": {
      "scopes": [],
      "roles": ["manager"],
      "groups": []
    }
  }
}

test_internal_human_operator := true if {
  allow with input as {
    "dataset": {"access_level": "internal"},
    "subject": {
      "scopes": [],
      "roles": ["operator"],
      "groups": []
    }
  }
}

test_internal_human_viewer_denied := true if {
  not allow with input as {
    "dataset": {"access_level": "internal"},
    "subject": {
      "scopes": [],
      "roles": ["viewer"],
      "groups": []
    }
  }
}

# -------------------------------------------------
# RESTRICTED — services
# -------------------------------------------------

test_restricted_service_with_admin_scope := true if {
  allow with input as {
    "dataset": {"access_level": "restricted"},
    "subject": {
      "scopes": ["dataset.admin"],
      "roles": [],
      "groups": []
    }
  }
}

test_restricted_service_with_query_scope_denied := true if {
  not allow with input as {
    "dataset": {"access_level": "restricted"},
    "subject": {
      "scopes": ["dataset.query"],
      "roles": [],
      "groups": []
    }
  }
}

# -------------------------------------------------
# RESTRICTED — humans
# -------------------------------------------------

test_restricted_human_admin := true if {
  allow with input as {
    "dataset": {"access_level": "restricted"},
    "subject": {
      "scopes": [],
      "roles": ["admin"],
      "groups": []
    }
  }
}

test_restricted_human_operator_denied := true if {
  not allow with input as {
    "dataset": {"access_level": "restricted"},
    "subject": {
      "scopes": [],
      "roles": ["operator"],
      "groups": []
    }
  }
}

# -------------------------------------------------
# SAFETY
# -------------------------------------------------

test_unknown_access_level_denied := true if {
  not allow with input as {
    "dataset": {"access_level": "classified"},
    "subject": {
      "scopes": ["dataset.admin"],
      "roles": ["admin"],
      "groups": []
    }
  }
}
