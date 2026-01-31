# METADATA
# title: Common Subject Helpers
# description: Shared utilities for subject type detection and authorization
# scope: package
package celine.common.subject

import rego.v1

# Check if subject is a human user
is_user if {
	input.subject.type == "user"
}

# Check if subject is a service client
is_service if {
	input.subject.type == "service"
}

# Check if subject is anonymous
is_anonymous if {
	input.subject == null
}

is_anonymous if {
	input.subject.type == "anonymous"
}

# Check if user is in a specific group
in_group(group) if {
	is_user
	group in input.subject.groups
}

# Check if user is in any of the specified groups
in_any_group(groups) if {
	is_user
	some group in groups
	group in input.subject.groups
}

# Check if subject has a specific scope (users and services).
# For user tokens, scopes represent the client scopes granted to the requesting client.
has_scope(scope) if {
	input.subject != null
	scope in input.subject.scopes
}

# Check if subject has any of the specified scopes (users and services).
has_any_scope(scopes) if {
	input.subject != null
	some scope in scopes
	scope in input.subject.scopes
}

# Get subject identifier safely
subject_id := id if {
	input.subject != null
	id := input.subject.id
} else := "anonymous"

# Group hierarchy check (admins > managers > editors > viewers)
# Returns true if user's highest group is at or above required level
has_group_level(required_level) if {
	is_user
	user_level := group_level(input.subject.groups)
	user_level >= required_level
}

# Map groups to numeric levels
group_level(groups) := 4 if {
	"admins" in groups
}

group_level(groups) := 3 if {
	not "admins" in groups
	"managers" in groups
}

group_level(groups) := 2 if {
	not "admins" in groups
	not "managers" in groups
	"editors" in groups
}

group_level(groups) := 1 if {
	not "admins" in groups
	not "managers" in groups
	not "editors" in groups
	"viewers" in groups
}

group_level(groups) := 0 if {
	not "admins" in groups
	not "managers" in groups
	not "editors" in groups
	not "viewers" in groups
}

# Level constants for readability
level_admin := 4
level_manager := 3
level_editor := 2
level_viewer := 1
