package celine.common.groups

is_authenticated if {
    input.user
}

is_admin if {
    is_authenticated
    "admins" in input.user.group_names
}

is_manager if {
    is_authenticated
    "managers" in input.user.group_names
}

is_editor if {
    is_authenticated
    "editors" in input.user.group_names
}

is_viewer if {
    is_authenticated
    "viewers" in input.user.group_names
}