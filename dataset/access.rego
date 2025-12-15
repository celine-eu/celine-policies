package celine.dataset.access

import data.celine.common.groups

default allow = false

#
# INTERNAL datasets
# - managers, editors, admins
#
allow {
    input.dataset.disclosure_level == "internal"
    groups.is_manager
}

allow {
    input.dataset.disclosure_level == "internal"
    groups.is_editor
}

allow {
    input.dataset.disclosure_level == "internal"
    groups.is_admin
}

#
# RESTRICTED datasets
# - owner OR admin
#
allow {
    input.dataset.disclosure_level == "restricted"
    input.user.sub == input.dataset.governance.owner
}

allow {
    input.dataset.disclosure_level == "restricted"
    groups.is_admin
}