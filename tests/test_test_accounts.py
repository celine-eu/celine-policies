"""`keycloak sync-test-accounts`: declared test accounts on a non-prod realm.

A test account stands for no person: it is declared by the deployment with a level of
authority (`platform-admin`, a group in each organization), marked by the realm group
`/test-accounts`, carries a placeholder profile, and gets its password from a template in
the environment — temporary (people) or fixed (automation). What is pinned:

- it runs only where ENV is exactly dev, staging or preprod, and refuses anything else
  (unset and empty included) before the file is read or Keycloak is asked anything;
- the declaration is checked whole: no password, e-mail or name, only known keys;
- an account is created in /test-accounts with the placeholder profile and the declared
  password mode, and a password is sent again only with --rotate, to fixed accounts;
- a test account holds exactly the declared authority, added and removed, and an account
  outside /test-accounts is never written, even in the same organization;
- a test account no longer declared is disabled, never deleted;
- a second run writes nothing, and a dry run writes nothing;
- output is usernames and counts, never a password.

@verifies REQ-0023
"""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from celine.policies.cli.keycloak.client import KeycloakError, KeycloakNotFoundError
from celine.policies.cli.keycloak.settings import (
    ADMIN_TEMP_PASSWORD_TEMPLATE,
    TEST_ACCOUNT_PASSWORD_TEMPLATE,
    password_for_test_account,
    platform_admin_password,
)
from celine.policies.cli.keycloak.test_accounts import (
    FIXED_LABEL,
    TEST_ACCOUNTS_GROUP,
    TEST_ACCOUNTS_MARKER,
    TEST_ACCOUNTS_MARKER_VALUE,
    TestAccountsRefused,
    parse_test_accounts,
    refusal,
    sync_test_accounts,
)
from celine.policies.cli.main import app

TEMPLATE = "Tpl-{username}-9x!"


def pw(username: str) -> str:
    return TEMPLATE.replace("{username}", username)


def no_template(username: str) -> None:
    return None


class FakeRealm:
    """Users, realm groups and organizations of one realm.

    It has no method that deletes a user: a run that tried would fail here.
    """

    def __init__(self, organizations: tuple[str, ...] = ("example-rec", "example-dso")):
        self.users: dict[str, dict[str, Any]] = {}
        self.groups: dict[str, dict[str, Any]] = {}
        self.group_members: dict[str, set[str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        self.roles: dict[str, set[str]] = {}
        self.credentials: dict[str, list[dict[str, Any]]] = {}
        self.passwords: dict[str, tuple[str, bool]] = {}
        self.realm_roles = {"platform-admin", "default-roles-celine"}
        self.writes: list[tuple] = []
        self.refuse_passwords = False
        self._n = 0
        for alias in organizations:
            self.add_organization(alias)

    # --- building a starting state ---

    def add_organization(self, alias: str, groups: tuple[str, ...] = ("admins", "managers", "editors", "viewers")) -> None:
        self.orgs[alias] = {
            "id": f"org-{alias}",
            "alias": alias,
            "members": {},
            "groups": {g: {"id": f"og-{alias}-{g}", "name": g, "members": set()} for g in groups},
        }

    def add_user(self, username: str, *, enabled: bool = True, marked: bool = False, **rep: Any) -> str:
        self._n += 1
        uid = f"u-{self._n}"
        self.users[uid] = {"id": uid, "username": username, "enabled": enabled, **rep}
        self.roles[uid] = set()
        self.credentials[uid] = []
        if marked:
            self.group_members[self.marker_group()].add(uid)
        return uid

    def marker_group(self, attributes: dict[str, list[str]] | None = None) -> str:
        for gid, g in self.groups.items():
            if g["path"] == TEST_ACCOUNTS_GROUP:
                return gid
        return self._add_group(
            TEST_ACCOUNTS_GROUP.lstrip("/"),
            {TEST_ACCOUNTS_MARKER: [TEST_ACCOUNTS_MARKER_VALUE]} if attributes is None else attributes,
        )

    def _add_group(self, name: str, attributes: dict[str, list[str]]) -> str:
        gid = f"g-{name}"
        self.groups[gid] = {"id": gid, "name": name, "path": f"/{name}", "attributes": attributes}
        self.group_members[gid] = set()
        return gid

    def join(self, alias: str, uid: str, group: str, managed: bool = False) -> None:
        org = self.orgs[alias]
        org["members"][uid] = "MANAGED" if managed else "UNMANAGED"
        org["groups"][group]["members"].add(uid)

    def uid(self, username: str) -> str:
        return next(u["id"] for u in self.users.values() if u["username"] == username)

    def user(self, username: str) -> dict[str, Any]:
        return self.users[self.uid(username)]

    def org_groups_of(self, alias: str, uid: str) -> set[str]:
        return {g for g, rep in self.orgs[alias]["groups"].items() if uid in rep["members"]}

    def is_marked(self, uid: str) -> bool:
        gid = next((g for g, r in self.groups.items() if r["path"] == TEST_ACCOUNTS_GROUP), None)
        return gid is not None and uid in self.group_members[gid]

    def _org_by_id(self, org_id: str) -> dict[str, Any]:
        return next(o for o in self.orgs.values() if o["id"] == org_id)

    # --- the client calls ---

    async def get_group_by_path(self, path):
        return next(({"id": g["id"], "path": g["path"]} for g in self.groups.values() if g["path"] == path), None)

    async def get_group(self, group_id):
        return dict(self.groups[group_id])

    async def get_group_members(self, group_id):
        return [dict(self.users[uid]) for uid in sorted(self.group_members[group_id])]

    async def create_group_with_attributes(self, name, attributes):
        self.writes.append(("create_group", name))
        return self._add_group(name, attributes)

    async def get_realm_role(self, name):
        return {"id": f"r-{name}", "name": name} if name in self.realm_roles else None

    async def get_user_by_username(self, username):
        return next((dict(u) for u in self.users.values() if u["username"] == username), None)

    async def get_user_by_id(self, user_id):
        u = self.users.get(user_id)
        return dict(u) if u else None

    async def create_user(self, username, *, email=None, first_name=None, last_name=None,
                          temporary_password=None, enabled=True, temporary=True,
                          email_verified=False, locale=None, groups=None):
        if self.refuse_passwords and temporary_password:
            raise KeycloakError("Unexpected response 400: invalidPasswordMinLengthMessage", status_code=400)
        self.writes.append(("create_user", username))
        rep = {"email": email, "firstName": first_name, "lastName": last_name, "emailVerified": email_verified}
        if temporary_password and temporary:
            rep["requiredActions"] = ["UPDATE_PASSWORD"]
        uid = self.add_user(username, enabled=enabled, **rep)
        for path in groups or []:
            gid = next(g for g, r in self.groups.items() if r["path"] == path)
            self.group_members[gid].add(uid)
        if temporary_password:
            self.passwords[uid] = (temporary_password, temporary)
            self.credentials[uid] = [{"id": f"c-{uid}", "type": "password"}]

    async def set_user_enabled(self, user_id, enabled):
        self.writes.append(("enabled", user_id, enabled))
        self.users[user_id]["enabled"] = enabled
        return True

    async def update_user_profile(self, user_id, *, first_name=None, last_name=None, email=None, email_verified=None):
        self.writes.append(("profile", user_id))
        self.users[user_id].update(firstName=first_name, lastName=last_name, email=email, emailVerified=email_verified)

    async def get_user_credentials(self, user_id):
        return [dict(c) for c in self.credentials[user_id]]

    async def set_credential_label(self, user_id, credential_id, label):
        self.writes.append(("label", user_id, label))
        for c in self.credentials[user_id]:
            if c["id"] == credential_id:
                c["userLabel"] = label

    async def set_user_password(self, user_id, password, temporary=True):
        if self.refuse_passwords:
            raise KeycloakError("Unexpected response 400: invalidPasswordHistoryMessage", status_code=400)
        self.writes.append(("password", user_id, temporary))
        self.passwords[user_id] = (password, temporary)
        self.credentials[user_id] = [{"id": f"c2-{user_id}", "type": "password"}]

    async def get_user_realm_role_names(self, user_id):
        return set(self.roles[user_id])

    async def add_user_realm_role(self, user_id, role):
        self.writes.append(("+role", user_id, role))
        self.roles[user_id].add(role)

    async def remove_user_realm_role(self, user_id, role):
        self.writes.append(("-role", user_id, role))
        self.roles[user_id].discard(role)

    async def get_organization_by_alias(self, alias):
        org = self.orgs.get(alias)
        return {"id": org["id"], "alias": alias} if org else None

    async def list_org_groups(self, org_id):
        return [{"id": g["id"], "name": g["name"]} for g in self._org_by_id(org_id)["groups"].values()]

    async def get_user_organizations(self, user_id):
        return [{"id": o["id"], "alias": o["alias"]} for o in self.orgs.values() if user_id in o["members"]]

    async def get_organization_member(self, org_id, user_id):
        org = self._org_by_id(org_id)
        if user_id not in org["members"]:
            return None
        return {"id": user_id, "membershipType": org["members"][user_id]}

    async def remove_user_from_organization(self, org_id, user_id):
        self.writes.append(("-org", user_id, org_id))
        org = self._org_by_id(org_id)
        org["members"].pop(user_id, None)
        for g in org["groups"].values():
            g["members"].discard(user_id)
        return True

    async def ensure_user_in_organization(self, org_id, user_id):
        self.writes.append(("+org", user_id, org_id))
        self._org_by_id(org_id)["members"].setdefault(user_id, "UNMANAGED")
        return True

    async def ensure_user_in_org_group(self, org_id, group_id, user_id):
        self.writes.append(("+group", user_id, group_id))
        org = self._org_by_id(org_id)
        if user_id not in org["members"]:
            raise KeycloakNotFoundError("not a member")
        next(g for g in org["groups"].values() if g["id"] == group_id)["members"].add(user_id)
        return True

    async def get_member_org_groups(self, org_id, user_id):
        org = self._org_by_id(org_id)
        return [{"id": g["id"], "name": g["name"]} for g in org["groups"].values() if user_id in g["members"]]

    async def remove_user_from_org_group(self, org_id, group_id, user_id):
        self.writes.append(("-group", user_id, group_id))
        org = self._org_by_id(org_id)
        next(g for g in org["groups"].values() if g["id"] == group_id)["members"].discard(user_id)
        return True


def declare(*users: dict[str, Any]):
    return parse_test_accounts({"users": list(users)})


async def run(realm: FakeRealm, *users: dict[str, Any], password_for=pw, **kw):
    return await sync_test_accounts(realm, declare(*users), password_for=password_for, **kw)


# ---------------------------------------------------------------------------
# The environment
# ---------------------------------------------------------------------------


class TestTheEnvironment:
    @pytest.mark.parametrize("env", ["dev", "staging", "preprod", "STAGING", " preprod "])
    def test_dev_staging_and_preprod_are_allowed(self, env):
        assert refusal(env) is None

    @pytest.mark.parametrize("env", [None, "", "  ", "prod", "production", "Production", "stage", "test"])
    def test_anything_else_is_refused_and_names_the_allowed_values(self, env):
        why = refusal(env)

        assert why is not None
        assert "dev, staging, preprod" in why


# ---------------------------------------------------------------------------
# The declaration
# ---------------------------------------------------------------------------


class TestTheDeclaration:
    def test_an_empty_list_is_allowed(self):
        assert parse_test_accounts({"users": []}) == []

    def test_the_defaults_are_temporary_enabled_and_no_authority(self):
        (a,) = declare({"username": "test-x"})

        assert (a.password, a.enabled, a.realm_roles, a.organizations) == ("temporary", True, frozenset(), ())

    def test_the_test_prefix_is_a_convention_not_a_check(self):
        (a,) = declare({"username": "scanner"})

        assert a.username == "scanner"

    @pytest.mark.parametrize("value", ["hunter2", "", True, None])
    def test_a_password_value_is_refused(self, value):
        with pytest.raises(ValueError, match="mode"):
            declare({"username": "test-x", "password": value})

    @pytest.mark.parametrize("key", ["email", "first_name", "last_name", "group", "attributes"])
    def test_a_profile_key_or_any_other_key_is_refused(self, key):
        with pytest.raises(ValueError, match="key"):
            declare({"username": "test-x", key: "v"})

    def test_a_username_declared_twice_is_refused(self):
        with pytest.raises(ValueError, match="twice"):
            declare({"username": "test-x"}, {"username": "test-x"})

    @pytest.mark.parametrize("username", ["Test-X", "test x", "", "a..b", None, "-x"])
    def test_a_username_unfit_for_the_placeholder_address_is_refused(self, username):
        with pytest.raises(ValueError, match="username"):
            declare({"username": username})

    def test_only_platform_admin_is_a_realm_role(self):
        with pytest.raises(ValueError, match="realm_roles"):
            declare({"username": "test-x", "realm_roles": ["admin"]})

    def test_an_organization_maps_to_one_of_its_groups(self):
        with pytest.raises(ValueError, match="organizations"):
            declare({"username": "test-x", "organizations": {"example-rec": "owners"}})

    def test_enabled_is_a_boolean(self):
        with pytest.raises(ValueError, match="enabled"):
            declare({"username": "test-x", "enabled": "no"})

    @pytest.mark.parametrize("data", [None, [], {"accounts": []}, {"users": {}}, {"users": [], "x": 1}])
    def test_anything_but_a_users_list_is_refused(self, data):
        with pytest.raises(ValueError, match="users"):
            parse_test_accounts(data)

    def test_one_bad_entry_refuses_the_whole_file(self):
        with pytest.raises(ValueError):
            declare({"username": "test-ok"}, {"username": "test-bad", "password": "secret"})


# ---------------------------------------------------------------------------
# Creating
# ---------------------------------------------------------------------------


class TestCreating:
    async def test_it_is_created_in_the_marker_group_with_the_placeholder_profile(self):
        realm = FakeRealm()

        report = await run(realm, {"username": "test-x"})

        u = realm.user("test-x")
        assert realm.is_marked(u["id"])
        assert (u["firstName"], u["lastName"], u["email"], u["emailVerified"]) == (
            "test-x", "test", "test-x@test.invalid", True
        )
        assert u["enabled"] is True
        assert report.counts["created"] == 1
        assert report.group_created

    async def test_the_marker_group_carries_the_marker(self):
        realm = FakeRealm()

        await run(realm, {"username": "test-x"})

        (g,) = [g for g in realm.groups.values() if g["path"] == TEST_ACCOUNTS_GROUP]
        assert g["attributes"] == {TEST_ACCOUNTS_MARKER: [TEST_ACCOUNTS_MARKER_VALUE]}

    async def test_a_temporary_account_gets_the_template_password_and_update_password(self):
        realm = FakeRealm()

        await run(realm, {"username": "test-x"})

        uid = realm.uid("test-x")
        assert realm.passwords[uid] == (pw("test-x"), True)
        assert realm.users[uid]["requiredActions"] == ["UPDATE_PASSWORD"]
        assert "userLabel" not in realm.credentials[uid][0]

    async def test_a_fixed_account_gets_the_template_password_without_a_required_action(self):
        realm = FakeRealm()

        await run(realm, {"username": "test-bot", "password": "fixed"})

        uid = realm.uid("test-bot")
        assert realm.passwords[uid] == (pw("test-bot"), False)
        assert "requiredActions" not in realm.users[uid]
        assert realm.credentials[uid][0]["userLabel"] == FIXED_LABEL

    async def test_an_account_declared_disabled_is_created_disabled(self):
        realm = FakeRealm()

        await run(realm, {"username": "test-old", "enabled": False})

        assert realm.user("test-old")["enabled"] is False

    async def test_it_gets_the_declared_authority(self):
        realm = FakeRealm()

        await run(
            realm,
            {"username": "test-admin", "realm_roles": ["platform-admin"],
             "organizations": {"example-rec": "admins", "example-dso": "viewers"}},
        )

        uid = realm.uid("test-admin")
        assert realm.roles[uid] == {"platform-admin"}
        assert realm.org_groups_of("example-rec", uid) == {"admins"}
        assert realm.org_groups_of("example-dso", uid) == {"viewers"}

    async def test_without_a_template_a_run_that_creates_is_refused_before_any_write(self):
        realm = FakeRealm()
        realm.add_user("test-keep", marked=True)

        with pytest.raises(TestAccountsRefused, match="TEMPLATE"):
            await run(realm, {"username": "test-new"}, {"username": "test-gone-from-file"}, password_for=no_template)

        assert realm.writes == []

    async def test_without_a_template_a_run_that_creates_nothing_runs(self):
        realm = FakeRealm()
        realm.marker_group()
        realm.add_user("test-x", marked=True, **_placeholder("test-x"))

        report = await run(realm, {"username": "test-x"}, password_for=no_template)

        assert report.counts["unchanged"] == 1

    async def test_a_password_the_realm_refuses_is_reported_and_creates_nothing(self):
        realm = FakeRealm()
        realm.refuse_passwords = True

        report = await run(realm, {"username": "test-x", "password": "fixed"})

        assert report.counts["password_refused"] == 1
        assert report.counts["created"] == 0
        assert report.needs_attention
        assert all(w[0] != "create_user" for w in realm.writes)
        assert report.changes == [("test-x", "not created: Keycloak refused the password (its policy)")]


def _placeholder(username: str) -> dict[str, Any]:
    return {"firstName": username, "lastName": "test", "email": f"{username}@test.invalid", "emailVerified": True}


# ---------------------------------------------------------------------------
# Passwords after creation
# ---------------------------------------------------------------------------


class TestPasswords:
    async def test_a_second_run_sends_no_password(self):
        realm = FakeRealm()
        users = ({"username": "test-x"}, {"username": "test-bot", "password": "fixed"})
        await run(realm, *users)
        realm.writes.clear()

        await run(realm, *users)

        assert realm.writes == []

    async def test_rotate_resets_enabled_fixed_accounts_only(self):
        realm = FakeRealm()
        users = (
            {"username": "test-person"},
            {"username": "test-bot", "password": "fixed"},
            {"username": "test-off", "password": "fixed", "enabled": False},
        )
        await run(realm, *users)
        realm.writes.clear()

        report = await run(realm, *users, password_for=lambda u: f"New-{u}-7!", rotate=True)

        assert [w for w in realm.writes if w[0] == "password"] == [("password", realm.uid("test-bot"), False)]
        assert realm.passwords[realm.uid("test-bot")] == ("New-test-bot-7!", False)
        assert realm.passwords[realm.uid("test-person")] == (pw("test-person"), True)
        assert realm.credentials[realm.uid("test-bot")][0]["userLabel"] == FIXED_LABEL
        assert report.counts["passwords_rotated"] == 1
        assert not report.needs_attention

    async def test_rotate_without_a_template_is_refused_before_any_write(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-bot", "password": "fixed"}, {"username": "test-x"})
        realm.writes.clear()

        with pytest.raises(TestAccountsRefused):
            await run(realm, {"username": "test-bot", "password": "fixed"}, password_for=no_template, rotate=True)

        assert realm.writes == []

    async def test_a_rotation_the_realm_refuses_is_reported(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-bot", "password": "fixed"})
        realm.refuse_passwords = True

        report = await run(realm, {"username": "test-bot", "password": "fixed"}, rotate=True)

        assert report.counts["password_refused"] == 1
        assert report.counts["passwords_rotated"] == 0
        assert report.needs_attention
        assert ("test-bot", "fixed password rotated") not in report.changes

    @pytest.mark.parametrize("made, declared", [("temporary", "fixed"), ("fixed", "temporary")])
    async def test_a_changed_mode_is_reported_and_not_applied(self, made, declared):
        realm = FakeRealm()
        await run(realm, {"username": "test-x", "password": made})
        realm.writes.clear()

        report = await run(realm, {"username": "test-x", "password": declared})

        assert realm.writes == []
        assert report.counts["mode_drift"] == 1
        assert report.needs_attention

    async def test_rotate_makes_an_account_declared_fixed_fixed(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-x"})

        await run(realm, {"username": "test-x", "password": "fixed"}, rotate=True)
        report = await run(realm, {"username": "test-x", "password": "fixed"})

        assert report.counts["mode_drift"] == 0
        assert report.counts["unchanged"] == 1


# ---------------------------------------------------------------------------
# Exactly the declared authority, on test accounts only
# ---------------------------------------------------------------------------


class TestExactAuthority:
    async def test_platform_admin_is_removed_when_no_longer_declared(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-x", "realm_roles": ["platform-admin"]})

        report = await run(realm, {"username": "test-x"})

        assert realm.roles[realm.uid("test-x")] == set()
        assert report.counts["realm_roles_removed"] == 1

    async def test_other_realm_roles_are_left_alone(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-x"})
        realm.roles[realm.uid("test-x")].add("default-roles-celine")

        await run(realm, {"username": "test-x"})

        assert realm.roles[realm.uid("test-x")] == {"default-roles-celine"}

    async def test_a_downgrade_takes_the_higher_group_away(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-x", "organizations": {"example-rec": "admins"}})

        report = await run(realm, {"username": "test-x", "organizations": {"example-rec": "viewers"}})

        assert realm.org_groups_of("example-rec", realm.uid("test-x")) == {"viewers"}
        assert (report.counts["groups_removed"], report.counts["groups_added"]) == (1, 1)

    async def test_an_organization_no_longer_declared_is_left(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-x", "organizations": {"example-rec": "admins", "example-dso": "admins"}})

        report = await run(realm, {"username": "test-x", "organizations": {"example-dso": "admins"}})

        uid = realm.uid("test-x")
        assert uid not in realm.orgs["example-rec"]["members"]
        assert realm.org_groups_of("example-dso", uid) == {"admins"}
        assert report.counts["organizations_left"] == 1

    async def test_a_person_in_the_same_organization_is_untouched(self):
        realm = FakeRealm()
        person = realm.add_user("ex-person", firstName="A", lastName="B", email="a@example.org")
        realm.join("example-rec", person, "admins")
        realm.roles[person].add("platform-admin")
        await run(realm, {"username": "test-x", "organizations": {"example-rec": "admins"}})

        await run(realm, {"username": "test-x", "organizations": {"example-rec": "viewers"}})
        await run(realm)

        assert realm.org_groups_of("example-rec", person) == {"admins"}
        assert realm.roles[person] == {"platform-admin"}
        assert realm.users[person]["enabled"] is True
        assert all(person not in w for w in realm.writes)

    async def test_a_managed_membership_is_kept_and_reported(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-x", "organizations": {"example-rec": "admins"}})
        realm.orgs["example-rec"]["members"][realm.uid("test-x")] = "MANAGED"

        report = await run(realm, {"username": "test-x"})

        assert realm.uid("test-x") in realm.orgs["example-rec"]["members"]
        assert report.counts["managed_memberships"] == 1
        assert report.needs_attention

    async def test_a_profile_edited_by_hand_is_put_back(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-x"})
        realm.user("test-x")["email"] = "someone@example.org"

        report = await run(realm, {"username": "test-x"})

        assert realm.user("test-x")["email"] == "test-x@test.invalid"
        assert report.counts["profile_written"] == 1


class TestOnlyTestAccounts:
    async def test_an_account_outside_the_group_holding_the_username_is_never_written(self):
        realm = FakeRealm()
        person = realm.add_user("test-x", email="p@example.org")

        report = await run(realm, {"username": "test-x", "realm_roles": ["platform-admin"]})

        assert realm.writes == []
        assert realm.roles[person] == set()
        assert report.counts["unmanaged_collisions"] == 1
        assert report.needs_attention

    async def test_an_account_outside_the_group_is_never_disabled(self):
        realm = FakeRealm()
        realm.marker_group()
        person = realm.add_user("ex-person")

        await run(realm)

        assert realm.users[person]["enabled"] is True

    async def test_a_group_of_that_name_without_the_marker_is_refused(self):
        realm = FakeRealm()
        realm.marker_group(attributes={})

        with pytest.raises(TestAccountsRefused, match=TEST_ACCOUNTS_MARKER):
            await run(realm, {"username": "test-x"})

        assert realm.writes == []

    @pytest.mark.parametrize("orgs, count", [({"example-x": "admins"}, "organization_missing"),
                                             ({"example-rec": "admins"}, "group_missing")])
    async def test_a_missing_organization_or_group_is_skipped_and_counted(self, orgs, count):
        realm = FakeRealm()
        realm.add_organization("example-rec", groups=("viewers",))

        report = await run(realm, {"username": "test-x", "organizations": orgs}, {"username": "test-y"})

        assert report.counts[count] == 1
        assert report.needs_attention
        assert [u["username"] for u in realm.users.values()] == ["test-y"]
        assert not realm.orgs.get("example-x")

    async def test_a_missing_realm_role_is_refused(self):
        realm = FakeRealm()
        realm.realm_roles.discard("platform-admin")

        with pytest.raises(TestAccountsRefused, match="bootstrap"):
            await run(realm, {"username": "test-x", "realm_roles": ["platform-admin"]})


# ---------------------------------------------------------------------------
# Disable, never delete; idempotence; dry run
# ---------------------------------------------------------------------------


class TestDisableAndIdempotence:
    async def test_an_account_no_longer_declared_is_disabled_and_kept(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-x"}, {"username": "test-y"})

        report = await run(realm, {"username": "test-y"})

        assert realm.user("test-x")["enabled"] is False
        assert report.counts["disabled"] == 1

    async def test_an_empty_declaration_disables_them_all(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-x"}, {"username": "test-y", "password": "fixed"})

        await run(realm)

        assert [u["enabled"] for u in realm.users.values()] == [False, False]

    async def test_declared_disabled_disables_and_enabled_again_enables(self):
        realm = FakeRealm()
        await run(realm, {"username": "test-x"})

        await run(realm, {"username": "test-x", "enabled": False})
        assert realm.user("test-x")["enabled"] is False
        await run(realm, {"username": "test-x"})
        assert realm.user("test-x")["enabled"] is True

    async def test_a_second_run_writes_nothing(self):
        realm = FakeRealm()
        users = (
            {"username": "test-admin", "realm_roles": ["platform-admin"], "organizations": {"example-rec": "admins"}},
            {"username": "test-bot", "password": "fixed", "organizations": {"example-dso": "viewers"}},
            {"username": "test-off", "enabled": False},
        )
        await run(realm, *users)
        realm.writes.clear()

        report = await run(realm, *users)

        assert realm.writes == []
        assert report.counts["unchanged"] == 3
        assert not report.needs_attention

    async def test_a_dry_run_writes_nothing_and_reports_what_a_run_would(self):
        realm = FakeRealm()
        users = ({"username": "test-x", "organizations": {"example-rec": "admins"}},)

        dry = await run(realm, *users, dry_run=True)
        assert realm.writes == [] and realm.users == {}
        real = await run(realm, *users)

        assert dry.counts == real.counts
        assert dry.changes == real.changes


# ---------------------------------------------------------------------------
# The template
# ---------------------------------------------------------------------------


class TestTheTemplate:
    def test_it_replaces_the_username(self):
        assert password_for_test_account("test-x", environ={TEST_ACCOUNT_PASSWORD_TEMPLATE: "{username}.Z1"}) == "test-x.Z1"

    def test_unset_or_empty_is_none(self):
        assert password_for_test_account("test-x", environ={}) is None
        assert password_for_test_account("test-x", environ={TEST_ACCOUNT_PASSWORD_TEMPLATE: ""}) is None

    def test_a_template_without_the_username_is_refused(self):
        with pytest.raises(ValueError, match=TEST_ACCOUNT_PASSWORD_TEMPLATE):
            password_for_test_account("test-x", environ={TEST_ACCOUNT_PASSWORD_TEMPLATE: "same"})

    def test_it_is_not_the_platform_admins_template(self):
        env = {ADMIN_TEMP_PASSWORD_TEMPLATE: "{username}-admin"}

        assert password_for_test_account("x", environ=env) is None
        assert platform_admin_password("x", environ=env) == "x-admin"


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------

runner = CliRunner()
CMD = "celine.policies.cli.keycloak.commands.sync_test_accounts"


@pytest.fixture
def declaration(tmp_path):
    path = tmp_path / "test-accounts.yaml"
    path.write_text(
        "users:\n"
        "  - username: test-rec-admin\n"
        "    organizations: { example-rec: admins }\n"
        "  - username: test-bot\n"
        "    password: fixed\n"
    )
    return path


@pytest.fixture
def fake_keycloak(monkeypatch):
    realm = FakeRealm()

    class Session:
        def __init__(self, settings):
            realm.settings = settings

        async def __aenter__(self):
            return realm

        async def __aexit__(self, *exc):
            return False

    async def authenticate():
        realm.authenticated = True

    realm.authenticate = authenticate
    monkeypatch.setattr(f"{CMD}.KeycloakAdminClient", Session)
    return realm


@pytest.fixture
def nothing_reached(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("read the file or reached Keycloak")

    monkeypatch.setattr(f"{CMD}.KeycloakAdminClient", boom)
    monkeypatch.setattr(f"{CMD}.load_test_accounts", boom)


def invoke(*args: str, env: dict[str, str] | None = None):
    base = {"CELINE_KEYCLOAK_BASE_URL": "https://keycloak.staging.example.org",
            "CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET": "x"}
    return runner.invoke(app, ["keycloak", "sync-test-accounts", *args], env={**base, **(env or {})})


class TestTheCommand:
    @pytest.mark.parametrize("env", [{}, {"ENV": ""}, {"ENV": "prod"}, {"ENV": "Production"}, {"ENV": "stage"},
                                     {"ENV": "staging", "CELINE_KEYCLOAK_ENV": "prod"},
                                     {"ENV": "staging", "CELINE_ENV": "production"}])
    @pytest.mark.parametrize("dry", [[], ["--dry-run"]])
    def test_a_refused_env_exits_1_before_the_file_is_read(self, env, dry, declaration, nothing_reached):
        result = invoke(str(declaration), *dry, env=env)

        assert result.exit_code == 1
        assert "dev, staging, preprod" in result.output

    def test_a_prefixed_variable_outranks_env(self, declaration, fake_keycloak):
        result = invoke(str(declaration), "--dry-run",
                        env={"ENV": "prod", "CELINE_KEYCLOAK_ENV": "preprod", TEST_ACCOUNT_PASSWORD_TEMPLATE: TEMPLATE})

        assert result.exit_code == 0, result.output

    def test_a_run_creates_and_prints_usernames_and_counts_never_a_password(self, declaration, fake_keycloak):
        result = invoke(str(declaration), env={"ENV": "staging", TEST_ACCOUNT_PASSWORD_TEMPLATE: TEMPLATE})

        assert result.exit_code == 0, result.output
        assert "test-rec-admin: created (temporary password)" in result.output
        assert "created: 2" in result.output
        assert pw("test-rec-admin") not in result.output and pw("test-bot") not in result.output
        assert "Tpl-" not in result.output

    def test_a_dry_run_writes_nothing(self, declaration, fake_keycloak):
        result = invoke(str(declaration), "--dry-run", env={"ENV": "staging", TEST_ACCOUNT_PASSWORD_TEMPLATE: TEMPLATE})

        assert result.exit_code == 0, result.output
        assert fake_keycloak.writes == []
        assert "would: test-bot: created (fixed password)" in result.output

    def test_no_template_where_one_is_needed_exits_1(self, declaration, fake_keycloak):
        result = invoke(str(declaration), env={"ENV": "staging"})

        assert result.exit_code == 1
        assert TEST_ACCOUNT_PASSWORD_TEMPLATE in result.output
        assert fake_keycloak.writes == []

    def test_a_template_without_the_username_exits_1_before_keycloak(self, declaration, nothing_reached):
        result = invoke(str(declaration), env={"ENV": "staging", TEST_ACCOUNT_PASSWORD_TEMPLATE: "same"})

        assert result.exit_code == 1
        assert "{username}" in result.output

    def test_a_malformed_declaration_exits_1(self, tmp_path, fake_keycloak):
        path = tmp_path / "bad.yaml"
        path.write_text("users:\n  - username: test-x\n    password: hunter2\n")

        result = invoke(str(path), env={"ENV": "staging"})

        assert result.exit_code == 1
        assert "hunter2" not in result.output
        assert not hasattr(fake_keycloak, "authenticated")

    def test_an_account_that_cannot_converge_exits_2(self, declaration, fake_keycloak):
        fake_keycloak.add_user("test-bot")

        result = invoke(str(declaration), env={"ENV": "dev", TEST_ACCOUNT_PASSWORD_TEMPLATE: TEMPLATE})

        assert result.exit_code == 2, result.output
        assert "unmanaged_collisions: 1" in result.output


def test_the_example_declaration_is_valid():
    from pathlib import Path

    from celine.policies.cli.keycloak.test_accounts import load_test_accounts

    accounts = load_test_accounts(Path(__file__).parent.parent / "config/keycloak/test-accounts.example.yaml")

    assert any(a.password == "fixed" for a in accounts)
    assert any("platform-admin" in a.realm_roles for a in accounts)
