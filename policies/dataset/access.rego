package celine.dataset.access

import data.celine.common.groups

default allow = false

#
# INTERNAL datasets
# - managers, editors, admins
#
allow if {
    input.dataset.access_level == "internal"
    groups.is_manager
}

allow if {
    input.dataset.access_level == "internal"
    groups.is_editor
}

allow if {
    input.dataset.access_level == "internal"
    groups.is_admin
}

#
# RESTRICTED datasets
# - owner OR admin
#
allow if {
    input.dataset.access_level == "restricted"
    input.user.sub == input.dataset.governance.owner
}

allow if {
    input.dataset.access_level == "restricted"
    groups.is_admin
}