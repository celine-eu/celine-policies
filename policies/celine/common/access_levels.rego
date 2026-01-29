# METADATA
# title: Access Level Helpers
# description: Shared utilities for resource access levels
# scope: package
package celine.common.access_levels

import rego.v1

# Access level hierarchy: open < internal < restricted
# Higher level means more sensitive

# Map access levels to numeric values
level_value(level) := 0 if level == "open"

level_value(level) := 1 if level == "internal"

level_value(level) := 2 if level == "restricted"

# Check if access level is at or below a threshold
is_open(level) if level == "open"

is_internal_or_below(level) if level in {"open", "internal"}

is_any_level(level) if level in {"open", "internal", "restricted"}

# Compare access levels
requires_at_least(required, actual) if {
	level_value(actual) >= level_value(required)
}
