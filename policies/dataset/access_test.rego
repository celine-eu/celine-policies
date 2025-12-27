package celine.dataset.access_test

import data.celine.dataset.access.allow

test_internal_allows_manager if {
    allow with input as {
        "dataset": {
            "access_level": "internal"
        },
        "user": {
            "sub": "u1",
            "group_names": ["managers"]
        }
    }
}

test_internal_denies_viewer if {
    not allow with input as {
        "dataset": {
            "access_level": "internal"
        },
        "user": {
            "sub": "u1",
            "group_names": ["viewers"]
        }
    }
}

test_restricted_allows_owner if {
    allow with input as {
        "dataset": {
            "access_level": "restricted",
            "governance": { "owner": "u1" }
        },
        "user": {
            "sub": "u1",
            "group_names": ["viewers"]
        }
    }
}

test_restricted_allows_admin if {
    allow with input as {
        "dataset": {
            "access_level": "restricted",
            "governance": { "owner": "u2" }
        },
        "user": {
            "sub": "admin-1",
            "group_names": ["admins"]
        }
    }
}