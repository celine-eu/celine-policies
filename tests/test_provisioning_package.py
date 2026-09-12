"""`celine.provisioning` makes exactly the calls `sync-users` used to make.

Phase 1 of the store's
`plans/provisioning-is-a-service-and-it-is-the-only-keycloak-writer.md` is a
refactor, so its test is that behaviour did not change — `test_sync_users_groups`
and `test_sync_users_check` still cover the command end to end against a fake
client. What is covered *here* is the extracted surface on its own, because the
service is about to become a second caller and the CLI's tests will not see it:
the call order, which of them are conditional, and the two places where doing
the obvious thing would be wrong.

Nothing here talks to a real Keycloak. The client is a recorder, so what is
pinned is which calls the package decides to make, not that Keycloak accepts
them — see the store's `playbooks/testing.md`.
"""

from __future__ import annotations

import pytest

from celine.policies.cli.keycloak.client import ROLE_HIERARCHY
from celine.provisioning import OrganizationSpec, Provisioner


class RecordingKeycloak:
    """Every Admin API call the provisioner makes, in order."""

    def __init__(self, *, existing_users: set[str] | None = None):
        self.existing_users = existing_users or set()
        self.calls: list[tuple] = []
        self.created_orgs: set[str] = set()
        self.created_groups: set[tuple[str, str]] = set()

    async def ensure_organization(self, *, alias, name, description, attributes):
        self.calls.append(("ensure_organization", alias, attributes))
        created = alias not in self.created_orgs
        self.created_orgs.add(alias)
        return f"org-{alias}", created

    async def ensure_org_role(self, org_id, role_name):
        self.calls.append(("ensure_org_role", org_id, role_name))

    async def ensure_org_group(self, org_id, name):
        self.calls.append(("ensure_org_group", org_id, name))
        created = (org_id, name) not in self.created_groups
        self.created_groups.add((org_id, name))
        return f"grp-{org_id}-{name}", created

    async def ensure_user(self, username, **kwargs):
        self.calls.append(("ensure_user", username, kwargs))
        if username in self.existing_users:
            return f"uuid-{username}", False
        self.existing_users.add(username)
        return f"uuid-{username}", True

    async def ensure_user_in_organization(self, org_id, user_id):
        self.calls.append(("ensure_user_in_organization", org_id, user_id))
        return True

    async def ensure_user_in_org_group(self, org_id, group_id, user_id):
        self.calls.append(("ensure_user_in_org_group", org_id, group_id, user_id))

    async def add_user_to_group_with_retry(self, user_id, group_id):
        self.calls.append(("add_user_to_group_with_retry", user_id, group_id))

    async def set_user_password(self, user_id, password, temporary=True):
        self.calls.append(("set_user_password", user_id, password, temporary))


@pytest.fixture
def kc() -> RecordingKeycloak:
    return RecordingKeycloak()


REC = OrganizationSpec(alias="greenland", name="Greenland", description="", type="rec")
DSO = OrganizationSpec(alias="edyna", name="Edyna", description="ops@edyna", type="dso")


# --- organizations --------------------------------------------------------


async def test_the_organization_type_attribute_separates_a_rec_from_an_operator(kc):
    """A DSO and a REC differ by one attribute, and nothing infers it."""
    await Provisioner(kc).ensure_community(REC, [DSO])

    types = {
        alias: attrs["type"]
        for call, alias, attrs in kc.calls
        if call == "ensure_organization"
    }
    assert types == {"greenland": ["rec"], "edyna": ["dso"]}


async def test_the_community_type_is_carried_through_rather_than_assumed(kc):
    """`type: energy-community` in the bundle reaches the organization intact."""
    spec = OrganizationSpec(alias="gl", name="GL", type="energy-community")
    await Provisioner(kc).ensure_community(spec)

    assert ("ensure_organization", "gl", {"type": ["energy-community"]}) in kc.calls


async def test_operators_are_ensured_before_the_community(kc):
    """The shared thing is made before the tenant thing, so a half-run is the
    useful half."""
    await Provisioner(kc).ensure_community(REC, [DSO])

    order = [alias for call, alias, _ in kc.calls if call == "ensure_organization"]
    assert order == ["edyna", "greenland"]


async def test_every_role_and_group_of_the_hierarchy_is_ensured_each_run(kc):
    """Not only on creation: an organization predating a name in the hierarchy is
    repaired by the next run, and that is the only repair there is."""
    provisioner = Provisioner(kc)
    await provisioner.ensure_community(REC)
    kc.calls.clear()
    await provisioner.ensure_community(REC)

    roles = [name for call, _, name in kc.calls if call == "ensure_org_role"]
    groups = [name for call, _, name in kc.calls if call == "ensure_org_group"]
    assert roles == ROLE_HIERARCHY
    assert groups == ROLE_HIERARCHY


async def test_the_member_group_is_viewers_and_comes_back_resolved(kc):
    """The id is returned rather than looked up again — a second lookup is a
    second chance to disagree."""
    outcome = await Provisioner(kc).ensure_community(REC)

    assert outcome.member_group_id == "grp-org-greenland-viewers"
    assert outcome.org_id == "org-greenland"


async def test_a_second_run_reports_nothing_created(kc):
    """What the caller prints is driven by these flags, so they have to be the
    truth and not the intent."""
    provisioner = Provisioner(kc)
    first = await provisioner.ensure_community(REC, [DSO])
    second = await provisioner.ensure_community(REC, [DSO])

    assert first.community.created and first.community.groups_created == tuple(
        ROLE_HIERARCHY
    )
    assert not second.community.created
    assert second.community.groups_created == ()
    assert [o.created for o in second.operators] == [False]


# --- participants ---------------------------------------------------------


async def test_the_account_exists_before_it_is_filed_anywhere(kc):
    """Keycloak will not accept the membership of a user it has not got, and the
    org group is addressed by the organization that owns it. Neither call is
    reorderable."""
    outcome = await Provisioner(kc).ensure_community(REC)
    kc.calls.clear()

    await Provisioner(kc).ensure_participant(
        username="gl-00001",
        org_id=outcome.org_id,
        member_group_id=outcome.member_group_id,
        password="pw",
    )

    assert [c[0] for c in kc.calls] == [
        "ensure_user",
        "ensure_user_in_organization",
        "ensure_user_in_org_group",
    ]


async def test_a_participant_is_filed_in_every_realm_group_the_caller_resolved(kc):
    """Resolution stays with the caller: a missing group has to stop a run before
    it has provisioned half of it, and this method only ever sees one member."""
    await Provisioner(kc).ensure_participant(
        username="gl-00001",
        org_id="org-greenland",
        realm_group_ids={"/participants": "g1", "/viewers": "g2"},
    )

    adds = [gid for call, _, gid in kc.calls if call == "add_user_to_group_with_retry"]
    assert adds == ["g1", "g2"]


async def test_no_org_group_call_when_the_caller_has_no_group_to_file_into(kc):
    outcome = await Provisioner(kc).ensure_participant(
        username="gl-00001", org_id="org-greenland", member_group_id=None
    )

    assert not any(c[0] == "ensure_user_in_org_group" for c in kc.calls)
    assert outcome.org_group_joined is False


async def test_an_existing_account_keeps_its_password(kc):
    """Resetting a credential because a reconcile ran is a denial of service with
    a schedule. It is opt-in, and this is the test that keeps it that way."""
    kc.existing_users.add("gl-00001")

    outcome = await Provisioner(kc).ensure_participant(
        username="gl-00001", org_id="org-greenland", password="pw"
    )

    assert not outcome.created
    assert not outcome.password_set
    assert not any(c[0] == "set_user_password" for c in kc.calls)


async def test_reset_password_reaches_an_account_that_already_existed(kc):
    kc.existing_users.add("gl-00001")

    outcome = await Provisioner(kc).ensure_participant(
        username="gl-00001",
        org_id="org-greenland",
        password="pw",
        temporary=False,
        reset_password=True,
    )

    assert outcome.password_set
    assert ("set_user_password", "uuid-gl-00001", "pw", False) in kc.calls


async def test_reset_password_does_not_re_set_a_credential_just_created(kc):
    """`ensure_user` already carried it. Setting it twice is one more write and
    one more chance for the two to disagree."""
    outcome = await Provisioner(kc).ensure_participant(
        username="gl-00001",
        org_id="org-greenland",
        password="pw",
        reset_password=True,
    )

    assert outcome.created and outcome.password_set
    assert not any(c[0] == "set_user_password" for c in kc.calls)


async def test_the_username_comes_back_with_the_keycloak_uuid_beside_it(kc):
    """`keycloak_id` is the uuid; the registry's `Member.user_id` is the
    username. The two names collide across the seam and this package uses
    neither ambiguously."""
    outcome = await Provisioner(kc).ensure_participant(
        username="a.person@example.org", org_id="org-greenland"
    )

    assert outcome.username == "a.person@example.org"
    assert outcome.keycloak_id == "uuid-a.person@example.org"
