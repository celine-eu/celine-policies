package celine.common.groups

is_authenticated {
    input.user
}

is_admin {
    "admins" in input.user.group_names
}

is_manager {
    "managers" in input.user.group_names
}

is_editor {
    "editors" in input.user.group_names
}

is_viewer {
    "viewers" in input.user.group_names
}