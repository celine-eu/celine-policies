"""`keycloak mirror-members`: an intermediate realm holds mirrors of the source's members.

A mirror is an account whose id is the member's account subject in the source realm and
whose username is the member's key there, with no e-mail, name or credential. The source is
prod's registry (`GET /admin/export/mirror`); the target is a non-prod realm. What is pinned:

- every member with a subject gets one mirror, in its community's organization and that
  organization's `viewers` group, enabled exactly when the member is active;
- nothing personal is ever written, and a member without a subject gets no account;
- an account the mirror did not make is never touched, whatever it collides with;
- a mirror whose member left or went inactive is disabled, never deleted;
- a second run writes nothing;
- the command refuses prod, and a target that is the source's own Keycloak.

@verifies REQ-0021
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from celine.policies.cli.keycloak import member_mirror
from celine.policies.cli.keycloak.client import (
    KeycloakAdminClient,
    KeycloakConflictError,
    KeycloakNotFoundError,
)
from celine.policies.cli.keycloak.member_mirror import (
    IMPERSONATION_PERMISSION,
    IMPERSONATION_SCOPES,
    IMPERSONATORS_POLICY,
    MIRROR_GROUP,
    MIRROR_MARKER,
    MirrorRefused,
    MirrorSourceError,
    mirror_members,
    parse_mirror_export,
    refusal,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.policies.cli.main import app

SOURCE = "https://keycloak.prod.example.org/realms/celine"
TARGET = "https://keycloak.staging.example.org"

SUB_A = "0b6f3c1e-7f0a-4c3e-9a51-0d6c2a1f0001"
SUB_B = "0b6f3c1e-7f0a-4c3e-9a51-0d6c2a1f0002"
SUB_C = "0b6f3c1e-7f0a-4c3e-9a51-0d6c2a1f0003"
SUB_D = "0b6f3c1e-7f0a-4c3e-9a51-0d6c2a1f0004"

#: Every key a mirror's representation may carry. Nothing personal is among them.
MIRROR_KEYS = {"id", "username", "enabled", "groups"}
PERSONAL_KEYS = {"email", "firstName", "lastName", "credentials", "attributes", "federatedIdentities"}


def member(key: str, subject: str | None, status: str = "active", **extra: Any) -> dict[str, Any]:
    return {
        "key": key,
        "area": "area-1",
        "role": "consumer",
        "type": "person",
        "status": status,
        "sensor_ids": ["s-1"],
        "subject": subject,
        **extra,
    }


def export(*members: dict[str, Any], community: str = "example-rec") -> dict[str, Any]:
    return {"communities": [{"community": community, "areas": {}, "members": list(members)}]}


# ---------------------------------------------------------------------------
# An in-memory realm answering the calls the mirror makes
# ---------------------------------------------------------------------------


class FakeRealm:
    """Users, realm groups, organizations and admin permissions of one realm.

    It has no method that deletes a user: a mirror that tried would fail here.
    """

    def __init__(self, *, organizations: tuple[str, ...] = ("example-rec",), admin_permissions: bool = True):
        self.users: dict[str, dict[str, Any]] = {}
        self.groups: dict[str, dict[str, Any]] = {}
        self.group_members: dict[str, set[str]] = {}
        self.orgs: dict[str, dict[str, Any]] = {}
        for alias in organizations:
            self.add_organization(alias)
        self.ap = "ap-uuid" if admin_permissions else None
        self.policies: dict[str, dict[str, Any]] = {}
        self.writes: list[tuple] = []
        self.imported: list[dict[str, Any]] = []

    # --- building a starting state ---

    def add_organization(self, alias: str, *, viewers: bool = True) -> None:
        groups = {"viewers": {"id": f"og-{alias}-viewers", "members": set()}} if viewers else {}
        self.orgs[alias] = {"id": f"org-{alias}", "alias": alias, "members": set(), "groups": groups}

    def add_user(self, user_id: str, username: str, *, enabled: bool = True, **rep: Any) -> None:
        self.users[user_id] = {"id": user_id, "username": username, "enabled": enabled, **rep}

    def add_group(self, name: str, attributes: dict[str, list[str]] | None = None) -> str:
        gid = f"g-{name}"
        self.groups[gid] = {"id": gid, "name": name, "path": f"/{name}", "attributes": attributes or {}}
        self.group_members[gid] = set()
        return gid

    def mirror_group_id(self) -> str | None:
        return next((g["id"] for g in self.groups.values() if g["path"] == MIRROR_GROUP), None)

    # --- users ---

    async def get_user_by_id(self, user_id):
        user = self.users.get(user_id)
        return dict(user) if user else None

    async def get_user_by_username(self, username):
        return next((dict(u) for u in self.users.values() if u["username"] == username.lower()), None)

    async def set_user_enabled(self, user_id, enabled):
        if self.users[user_id]["enabled"] == enabled:
            return False
        self.writes.append(("enabled", user_id, enabled))
        self.users[user_id]["enabled"] = enabled
        return True

    async def partial_import(self, payload):
        assert payload["ifResourceExists"] == "FAIL"
        for rep in payload["users"]:
            if rep["id"] in self.users or any(u["username"] == rep["username"] for u in self.users.values()):
                raise KeycloakConflictError("exists", status_code=409)
        self.writes.append(("import", len(payload["users"])))
        for rep in payload["users"]:
            self.imported.append(rep)
            self.add_user(rep["id"], rep["username"].lower(), enabled=rep["enabled"])
            for path in rep.get("groups", []):
                gid = next(g["id"] for g in self.groups.values() if g["path"] == path)
                self.group_members[gid].add(rep["id"])
        return {"added": len(payload["users"]), "overwritten": 0, "skipped": 0}

    # --- realm groups ---

    async def get_group_by_path(self, path):
        group = next((g for g in self.groups.values() if g["path"] == path), None)
        return {k: v for k, v in group.items() if k != "attributes"} if group else None

    async def get_group(self, group_id):
        return dict(self.groups[group_id])

    async def create_group_with_attributes(self, name, attributes):
        self.writes.append(("group", name))
        return self.add_group(name, attributes)

    async def get_group_members(self, group_id):
        return [dict(self.users[uid]) for uid in sorted(self.group_members[group_id])]

    # --- organizations ---

    async def get_organization_by_alias(self, alias):
        org = self.orgs.get(alias)
        return {"id": org["id"], "alias": alias} if org else None

    async def get_org_group_by_name(self, org_id, name):
        org = next(o for o in self.orgs.values() if o["id"] == org_id)
        group = org["groups"].get(name)
        return {"id": group["id"], "name": name} if group else None

    def _org(self, org_id):
        return next(o for o in self.orgs.values() if o["id"] == org_id)

    async def is_user_in_organization(self, org_id, user_id):
        return user_id in self._org(org_id)["members"]

    async def add_user_to_organization(self, org_id, user_id):
        assert user_id in self.users
        self.writes.append(("org", org_id, user_id))
        self._org(org_id)["members"].add(user_id)

    async def is_user_in_org_group(self, org_id, group_id, user_id):
        org = self._org(org_id)
        return any(g["id"] == group_id and user_id in g["members"] for g in org["groups"].values())

    async def ensure_user_in_org_group(self, org_id, group_id, user_id):
        org = self._org(org_id)
        assert user_id in org["members"], "Keycloak refuses a group to a non-member"
        self.writes.append(("org-group", group_id, user_id))
        next(g for g in org["groups"].values() if g["id"] == group_id)["members"].add(user_id)
        return True

    def in_org(self, alias, user_id):
        org = self.orgs[alias]
        return user_id in org["members"] and user_id in org["groups"]["viewers"]["members"]

    # --- admin permissions ---

    async def get_admin_permissions_client_uuid(self):
        return self.ap

    async def find_admin_policy_by_name(self, ap_uuid, name):
        policy = self.policies.get(name)
        return dict(policy) if policy else None

    @staticmethod
    def admin_policy_user_ids(policy):
        return KeycloakAdminClient.admin_policy_user_ids(policy)

    async def create_admin_user_policy(self, ap_uuid, name, user_ids):
        self.writes.append(("user-policy", name))
        # As a listing returns it: the users JSON-encoded inside `config`.
        self.policies[name] = {"id": f"p-{name}", "name": name, "type": "user",
                               "config": {"users": json.dumps(sorted(user_ids))}}
        return f"p-{name}"

    async def update_admin_user_policy(self, ap_uuid, policy_id, name, user_ids):
        self.writes.append(("user-policy-update", name))
        self.policies[name]["config"] = {"users": json.dumps(sorted(user_ids))}

    async def put_group_scope_permission(self, ap_uuid, permission_id, *, name, description, group_id, scopes, policy_id):
        self.writes.append(("permission", name))
        self.policies[name] = {"id": permission_id or f"p-{name}", "name": name, "type": "scope",
                               "_group": group_id, "_scopes": sorted(scopes), "_policies": [policy_id]}
        return self.policies[name]["id"]

    async def get_admin_permission_scopes(self, ap_uuid, permission_id):
        p = next(p for p in self.policies.values() if p["id"] == permission_id)
        return [{"name": s} for s in p["_scopes"]]

    async def get_admin_permission_resources(self, ap_uuid, permission_id):
        p = next(p for p in self.policies.values() if p["id"] == permission_id)
        return [{"_id": "res-x", "name": p["_group"]}]

    async def get_admin_permission_policies(self, ap_uuid, permission_id):
        p = next(p for p in self.policies.values() if p["id"] == permission_id)
        return [{"id": pid} for pid in p["_policies"]]


async def run(realm: FakeRealm, data: dict[str, Any], *, dry_run: bool = False, impersonators=()):
    return await mirror_members(
        realm, parse_mirror_export(data), source=SOURCE, dry_run=dry_run, impersonators=list(impersonators)
    )


# ---------------------------------------------------------------------------
# What a mirror is
# ---------------------------------------------------------------------------


class TestAMirror:
    async def test_it_keeps_the_subject_as_id_and_the_key_as_username(self):
        realm = FakeRealm()

        report = await run(realm, export(member("ex-00001", SUB_A)))

        assert realm.users[SUB_A]["username"] == "ex-00001"
        assert realm.users[SUB_A]["enabled"] is True
        assert report.counts["created"] == 1

    async def test_it_is_in_the_community_organization_and_its_viewers(self):
        realm = FakeRealm()

        await run(realm, export(member("ex-00001", SUB_A)))

        assert realm.in_org("example-rec", SUB_A)

    async def test_it_carries_the_marker_group_and_the_group_names_its_source(self):
        realm = FakeRealm()

        await run(realm, export(member("ex-00001", SUB_A)))

        gid = realm.mirror_group_id()
        assert gid is not None and SUB_A in realm.group_members[gid]
        assert realm.groups[gid]["attributes"] == {MIRROR_MARKER: [SOURCE]}

    async def test_nothing_personal_is_written(self):
        realm = FakeRealm()

        await run(realm, export(member("ex-00001", SUB_A, name="A Person", email="a.person@example.org")))

        (rep,) = realm.imported
        assert set(rep) <= MIRROR_KEYS
        assert not set(rep) & PERSONAL_KEYS
        assert "a.person@example.org" not in json.dumps(rep)

    async def test_an_inactive_member_is_mirrored_disabled(self):
        realm = FakeRealm()

        await run(realm, export(member("ex-00001", SUB_A, status="suspended")))

        assert realm.users[SUB_A]["enabled"] is False

    async def test_a_member_without_a_subject_gets_no_account(self):
        realm = FakeRealm()

        report = await run(realm, export(member("ex-00001", None), member("ex-00002", SUB_B)))

        assert set(realm.users) == {SUB_B}
        assert report.counts["without_subject"] == 1
        assert not report.needs_attention

    async def test_a_mixed_case_key_is_the_lowercased_username(self):
        """Keycloak stores usernames lower-cased; comparing any other form would
        make every run see a renamed member."""
        realm = FakeRealm()
        await run(realm, export(member("EX-00001", SUB_A)))

        report = await run(realm, export(member("EX-00001", SUB_A)))

        assert realm.users[SUB_A]["username"] == "ex-00001"
        assert report.counts["unchanged"] == 1


class TestIdempotence:
    async def test_a_second_run_writes_nothing(self):
        realm = FakeRealm()
        data = export(member("ex-00001", SUB_A), member("ex-00002", SUB_B, status="inactive"))
        await run(realm, data)
        realm.writes.clear()

        report = await run(realm, data)

        assert realm.writes == []
        assert report.counts["unchanged"] == 2
        assert report.counts["created"] == 0

    async def test_a_dry_run_writes_nothing_and_counts_what_a_run_would_do(self):
        realm = FakeRealm()
        data = export(member("ex-00001", SUB_A), member("ex-00002", None))

        dry = await run(realm, data, dry_run=True)

        assert realm.writes == [] and realm.users == {} and realm.groups == {}
        real = await run(FakeRealm(), data)
        assert dry.counts == real.counts


class TestDisableNeverDelete:
    async def test_a_member_gone_from_the_source_is_disabled_and_kept(self):
        realm = FakeRealm()
        await run(realm, export(member("ex-00001", SUB_A), member("ex-00002", SUB_B)))

        report = await run(realm, export(member("ex-00002", SUB_B)))

        assert realm.users[SUB_A]["enabled"] is False
        assert SUB_A in realm.users
        assert realm.in_org("example-rec", SUB_A)
        assert report.counts["disabled"] == 1

    async def test_a_member_turned_inactive_is_disabled(self):
        realm = FakeRealm()
        await run(realm, export(member("ex-00001", SUB_A)))

        report = await run(realm, export(member("ex-00001", SUB_A, status="suspended")))

        assert realm.users[SUB_A]["enabled"] is False
        assert report.counts["disabled"] == 1

    async def test_a_member_active_again_is_enabled(self):
        realm = FakeRealm()
        await run(realm, export(member("ex-00001", SUB_A, status="suspended")))

        report = await run(realm, export(member("ex-00001", SUB_A)))

        assert realm.users[SUB_A]["enabled"] is True
        assert report.counts["enabled"] == 1


class TestUnmanagedAccounts:
    async def test_an_account_holding_the_username_is_untouched(self):
        realm = FakeRealm()
        realm.add_user("native-1", "ex-00001", email="someone@example.org")

        report = await run(realm, export(member("ex-00001", SUB_A)))

        assert realm.users == {"native-1": {"id": "native-1", "username": "ex-00001",
                                            "enabled": True, "email": "someone@example.org"}}
        assert realm.writes == []
        assert report.counts["unmanaged_collisions"] == 1
        assert report.needs_attention

    async def test_an_account_holding_the_subject_is_untouched(self):
        realm = FakeRealm()
        realm.add_user(SUB_A, "someone-else")

        report = await run(realm, export(member("ex-00001", SUB_A)))

        assert realm.users[SUB_A]["username"] == "someone-else"
        assert report.counts["unmanaged_collisions"] == 1

    async def test_an_unmanaged_account_is_never_disabled(self):
        realm = FakeRealm()
        realm.add_user("native-1", "a-native-account")
        await run(realm, export(member("ex-00001", SUB_A)))

        await run(realm, export())

        assert realm.users["native-1"]["enabled"] is True

    async def test_a_username_held_by_another_mirror_is_skipped(self):
        """The source gave a key to a new subject: the old mirror keeps it until it is
        disabled; the new one is reported, not forced in."""
        realm = FakeRealm()
        await run(realm, export(member("ex-00001", SUB_A)))

        report = await run(realm, export(member("ex-00001", SUB_B)))

        assert SUB_B not in realm.users
        assert report.counts["username_taken"] == 1
        assert report.needs_attention

    async def test_a_changed_key_is_reported_and_not_renamed(self):
        realm = FakeRealm()
        await run(realm, export(member("ex-00001", SUB_A)))
        realm.writes.clear()

        report = await run(realm, export(member("ex-00009", SUB_A)))

        assert realm.users[SUB_A]["username"] == "ex-00001"
        assert realm.writes == []
        assert report.counts["key_changed"] == 1


class TestTheExport:
    async def test_one_subject_under_two_keys_is_skipped(self):
        realm = FakeRealm(organizations=("example-rec", "example-rec-2"))
        data = {"communities": [
            {"community": "example-rec", "members": [member("ex-00001", SUB_A)]},
            {"community": "example-rec-2", "members": [member("ex-00002", SUB_A)]},
        ]}

        report = await run(realm, data)

        assert realm.users == {}
        assert report.counts["export_conflicts"] == 1

    async def test_one_key_under_two_subjects_is_skipped(self):
        realm = FakeRealm(organizations=("example-rec", "example-rec-2"))
        data = {"communities": [
            {"community": "example-rec", "members": [member("ex-00001", SUB_A)]},
            {"community": "example-rec-2", "members": [member("ex-00001", SUB_B)]},
        ]}

        report = await run(realm, data)

        assert realm.users == {}
        assert report.counts["export_conflicts"] == 2

    async def test_one_subject_in_two_communities_joins_both(self):
        realm = FakeRealm(organizations=("example-rec", "example-rec-2"))
        data = {"communities": [
            {"community": "example-rec", "members": [member("ex-00001", SUB_A, status="inactive")]},
            {"community": "example-rec-2", "members": [member("ex-00001", SUB_A)]},
        ]}

        await run(realm, data)

        assert realm.in_org("example-rec", SUB_A) and realm.in_org("example-rec-2", SUB_A)
        assert realm.users[SUB_A]["enabled"] is True

    async def test_a_community_without_an_organization_creates_nobody(self):
        realm = FakeRealm(organizations=())

        report = await run(realm, export(member("ex-00001", SUB_A)))

        assert realm.users == {}
        assert report.counts["organization_missing"] == 1
        assert report.missing_organizations == {"example-rec"}
        assert report.needs_attention

    async def test_an_organization_without_viewers_counts_as_missing(self):
        realm = FakeRealm(organizations=())
        realm.add_organization("example-rec", viewers=False)

        report = await run(realm, export(member("ex-00001", SUB_A)))

        assert realm.users == {}
        assert report.counts["organization_missing"] == 1

    def test_a_subject_is_stored_lower_case(self):
        (m,) = parse_mirror_export(export(member("ex-00001", SUB_A.upper())))

        assert m.subject == SUB_A

    def test_a_subject_that_is_not_a_uuid_is_counted_and_skipped(self):
        (m,) = parse_mirror_export(export(member("ex-00001", "not-a-uuid")))

        assert m.subject is None and m.invalid_subject

    @pytest.mark.parametrize(
        "data",
        [
            [],
            {},
            {"communities": {}},
            {"communities": [{"members": []}]},
            {"communities": [{"community": "example-rec", "members": [{"subject": SUB_A}]}]},
            {"communities": [{"community": "example-rec", "members": [member("", SUB_A)]}]},
        ],
        ids=["list", "no-communities", "communities-not-a-list", "no-key", "member-no-key", "empty-key"],
    )
    def test_a_malformed_export_is_refused_whole(self, data):
        with pytest.raises(MirrorSourceError):
            parse_mirror_export(data)


class TestTheMarkerGroup:
    async def test_a_group_of_that_name_not_made_by_this_source_is_refused(self):
        realm = FakeRealm()
        realm.add_group(MIRROR_GROUP.lstrip("/"))

        with pytest.raises(MirrorRefused):
            await run(realm, export(member("ex-00001", SUB_A)))

        assert realm.writes == []

    async def test_a_group_made_by_another_source_is_refused(self):
        realm = FakeRealm()
        realm.add_group(MIRROR_GROUP.lstrip("/"), {MIRROR_MARKER: ["https://elsewhere.example.org/realms/celine"]})

        with pytest.raises(MirrorRefused):
            await run(realm, export(member("ex-00001", SUB_A)))

        assert realm.writes == []


class TestImpersonation:
    async def test_named_accounts_may_impersonate_the_mirror_group_only(self):
        realm = FakeRealm()
        realm.add_user("team-1", "team-account-1")

        await run(realm, export(member("ex-00001", SUB_A)), impersonators=["team-account-1"])

        policy = realm.policies[IMPERSONATORS_POLICY]
        assert KeycloakAdminClient.admin_policy_user_ids(policy) == {"team-1"}
        permission = realm.policies[IMPERSONATION_PERMISSION]
        assert permission["_group"] == realm.mirror_group_id()
        assert permission["_scopes"] == sorted(IMPERSONATION_SCOPES)
        assert permission["_policies"] == [policy["id"]]
        assert "impersonate-members" in IMPERSONATION_SCOPES
        assert not set(IMPERSONATION_SCOPES) & {"manage", "manage-members", "manage-membership"}

    async def test_a_second_run_rewrites_nothing(self):
        realm = FakeRealm()
        realm.add_user("team-1", "team-account-1")
        data = export(member("ex-00001", SUB_A))
        await run(realm, data, impersonators=["team-account-1"])
        realm.writes.clear()

        await run(realm, data, impersonators=["team-account-1"])

        assert realm.writes == []

    async def test_a_changed_list_rewrites_the_policy(self):
        realm = FakeRealm()
        realm.add_user("team-1", "team-account-1")
        realm.add_user("team-2", "team-account-2")
        await run(realm, export(), impersonators=["team-account-1"])

        await run(realm, export(), impersonators=["team-account-1", "team-account-2"])

        assert KeycloakAdminClient.admin_policy_user_ids(realm.policies[IMPERSONATORS_POLICY]) == {"team-1", "team-2"}

    async def test_an_account_that_does_not_exist_is_reported(self):
        realm = FakeRealm()
        realm.add_user("team-1", "team-account-1")

        report = await run(realm, export(), impersonators=["team-account-1", "nobody"])

        assert report.counts["impersonators_missing"] == 1
        assert report.needs_attention

    async def test_a_mirror_cannot_be_an_impersonator(self):
        realm = FakeRealm()
        await run(realm, export(member("ex-00001", SUB_A)))

        report = await run(realm, export(member("ex-00001", SUB_A)), impersonators=["ex-00001"])

        assert IMPERSONATORS_POLICY not in realm.policies
        assert report.counts["impersonators_refused"] == 1

    async def test_no_list_leaves_the_permission_alone(self):
        realm = FakeRealm()

        await run(realm, export(member("ex-00001", SUB_A)))

        assert realm.policies == {}

    async def test_a_realm_without_admin_permissions_is_refused(self):
        realm = FakeRealm(admin_permissions=False)
        realm.add_user("team-1", "team-account-1")

        with pytest.raises(MirrorRefused):
            await run(realm, export(), impersonators=["team-account-1"])


# ---------------------------------------------------------------------------
# Where it may run
# ---------------------------------------------------------------------------


class TestRefusal:
    @pytest.mark.parametrize("env", ["prod", "production", "PROD", " Production "])
    def test_prod_is_refused(self, env):
        assert refusal(env=env, target_base_url=TARGET, source_issuer=SOURCE)

    @pytest.mark.parametrize("env", ["staging", "dev", "preprod"])
    def test_an_intermediate_environment_runs(self, env):
        assert refusal(env=env, target_base_url=TARGET, source_issuer=SOURCE) is None

    def test_the_source_keycloak_as_target_is_refused(self):
        assert refusal(env="staging", target_base_url="https://keycloak.prod.example.org/", source_issuer=SOURCE)

    def test_the_host_comparison_ignores_case_and_port(self):
        assert refusal(env="staging", target_base_url="https://KEYCLOAK.prod.example.org:443", source_issuer=SOURCE)


runner = CliRunner()


@pytest.fixture
def export_file(tmp_path):
    path = tmp_path / "mirror.json"
    path.write_text(json.dumps(export(member("ex-00001", SUB_A), member("ex-00002", None))))
    return path


@pytest.fixture
def fake_keycloak(monkeypatch):
    """The command's Keycloak client, replaced by a FakeRealm it can sign in to."""
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
    monkeypatch.setattr("celine.policies.cli.keycloak.commands.mirror_members.KeycloakAdminClient", Session)
    return realm


@pytest.fixture
def nothing_reached(monkeypatch):
    """Fail the test if the command reads the source or opens Keycloak."""

    def boom(*a, **k):
        raise AssertionError("reached the source or Keycloak")

    monkeypatch.setattr("celine.policies.cli.keycloak.commands.mirror_members.KeycloakAdminClient", boom)
    monkeypatch.setattr("celine.policies.cli.keycloak.commands.mirror_members.fetch_mirror_export", boom)
    monkeypatch.setattr("celine.policies.cli.keycloak.commands.mirror_members.read_mirror_file", boom)


def invoke(*args: str, env: dict[str, str] | None = None):
    base = {"CELINE_KEYCLOAK_BASE_URL": TARGET, "CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET": "x"}
    return runner.invoke(app, ["keycloak", "mirror-members", *args], env={**base, **(env or {})})


class TestTheCommand:
    @pytest.mark.parametrize("env", [None, "prod", "production"])
    def test_prod_and_an_unset_env_are_refused_before_anything_is_read(self, env, export_file, nothing_reached):
        result = invoke("--from-file", str(export_file), "--source-issuer", SOURCE,
                        env={"ENV": env} if env else None)

        assert result.exit_code == 1
        assert "ENV" in result.output

    def test_the_source_keycloak_as_target_is_refused_before_anything_is_read(self, export_file, nothing_reached):
        result = invoke("--from-file", str(export_file), "--source-issuer", SOURCE,
                        env={"ENV": "staging", "CELINE_KEYCLOAK_BASE_URL": "https://keycloak.prod.example.org"})

        assert result.exit_code == 1

    def test_the_source_issuer_is_required(self, export_file, nothing_reached):
        result = invoke("--from-file", str(export_file), env={"ENV": "staging"})

        assert result.exit_code == 1

    def test_two_sources_are_refused(self, export_file, nothing_reached):
        result = invoke("--from-file", str(export_file), "--source-url", "https://api.prod.example.org/rec-registry",
                        "--source-issuer", SOURCE, env={"ENV": "staging"})

        assert result.exit_code == 1

    def test_no_source_is_refused(self, nothing_reached):
        result = invoke("--source-issuer", SOURCE, env={"ENV": "staging"})

        assert result.exit_code == 1

    def test_the_registry_needs_a_client_secret(self, nothing_reached):
        result = invoke("--source-url", "https://api.prod.example.org/rec-registry", "--source-issuer", SOURCE,
                        env={"ENV": "staging"})

        assert result.exit_code == 1
        assert "CELINE_MEMBER_MIRROR_SOURCE_CLIENT_SECRET" in result.output

    def test_a_run_prints_counts_and_no_member(self, export_file, fake_keycloak):
        result = invoke("--from-file", str(export_file), "--source-issuer", SOURCE, env={"ENV": "staging"})

        assert result.exit_code == 0, result.output
        assert "created: 1" in result.output
        assert "without_subject: 1" in result.output
        for value in ("ex-00001", "ex-00002", SUB_A):
            assert value not in result.output
        assert SUB_A in fake_keycloak.users

    def test_a_dry_run_writes_nothing(self, export_file, fake_keycloak):
        result = invoke("--from-file", str(export_file), "--source-issuer", SOURCE, "--dry-run",
                        env={"ENV": "staging"})

        assert result.exit_code == 0, result.output
        assert fake_keycloak.writes == []
        assert "dry run" in result.output.lower()

    def test_a_skipped_member_exits_2(self, export_file, fake_keycloak):
        fake_keycloak.add_user("native-1", "ex-00001")

        result = invoke("--from-file", str(export_file), "--source-issuer", SOURCE, env={"ENV": "staging"})

        assert result.exit_code == 2
        assert "unmanaged_collisions: 1" in result.output

    def test_impersonators_come_from_the_environment(self, export_file, fake_keycloak):
        fake_keycloak.add_user("team-1", "team-account-1")
        fake_keycloak.add_user("team-2", "team-account-2")

        result = invoke("--from-file", str(export_file), "--source-issuer", SOURCE,
                        env={"ENV": "staging", "CELINE_MEMBER_MIRROR_IMPERSONATORS": "team-account-1 team-account-2"})

        assert result.exit_code == 0, result.output
        policy = fake_keycloak.policies[IMPERSONATORS_POLICY]
        assert KeycloakAdminClient.admin_policy_user_ids(policy) == {"team-1", "team-2"}

    def test_a_malformed_file_exits_1(self, tmp_path, fake_keycloak):
        path = tmp_path / "bad.json"
        path.write_text("{}")

        result = invoke("--from-file", str(path), "--source-issuer", SOURCE, env={"ENV": "staging"})

        assert result.exit_code == 1
        assert fake_keycloak.writes == []


# ---------------------------------------------------------------------------
# Reading the source
# ---------------------------------------------------------------------------


class TestFetch:
    async def test_it_gets_the_mirror_export_with_a_bearer_token(self, monkeypatch):
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json=export())

        class Provider:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                Provider.last = self

            async def get_token(self):
                class T:
                    access_token = "tok"
                return T()

        monkeypatch.setattr(member_mirror, "_token_provider", Provider)

        data = await member_mirror.fetch_mirror_export(
            source_url="https://api.prod.example.org/rec-registry/",
            issuer=SOURCE,
            client_id="svc-member-mirror",
            client_secret="s",
            transport=httpx.MockTransport(handler),
        )

        assert data == export()
        assert str(seen[0].url) == "https://api.prod.example.org/rec-registry/admin/export/mirror"
        assert seen[0].headers["authorization"] == "Bearer tok"
        assert Provider.last.kwargs["base_url"] == SOURCE
        assert Provider.last.kwargs["client_id"] == "svc-member-mirror"

    @pytest.mark.parametrize("status", [401, 403, 404, 500])
    async def test_a_refusal_names_the_url_and_the_client_but_no_secret(self, monkeypatch, status):
        class Provider:
            def __init__(self, **kwargs):
                pass

            async def get_token(self):
                class T:
                    access_token = "tok"
                return T()

        monkeypatch.setattr(member_mirror, "_token_provider", Provider)

        with pytest.raises(MirrorSourceError) as caught:
            await member_mirror.fetch_mirror_export(
                source_url="https://api.prod.example.org/rec-registry",
                issuer=SOURCE,
                client_id="svc-member-mirror",
                client_secret="very-secret",
                transport=httpx.MockTransport(lambda r: httpx.Response(status, text="no")),
            )

        message = str(caught.value)
        assert "svc-member-mirror" in message and str(status) in message
        assert "very-secret" not in message


# ---------------------------------------------------------------------------
# The Admin API calls the mirror adds to the client
# ---------------------------------------------------------------------------


def _client(handler) -> KeycloakAdminClient:
    client = KeycloakAdminClient(KeycloakSettings(base_url="http://kc.test", realm="celine",
                                                  admin_user="admin", admin_password="admin"))
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def no_auth() -> dict[str, str]:
        return {}

    client._headers = no_auth  # type: ignore[method-assign]
    return client


class TestClientCalls:
    async def test_partial_import_posts_to_the_realm(self):
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, json={"added": 1})

        payload = {"ifResourceExists": "FAIL", "users": [{"id": SUB_A, "username": "ex-00001"}]}
        result = await _client(handler).partial_import(payload)

        assert result == {"added": 1}
        assert seen[0].method == "POST"
        assert seen[0].url.path == "/admin/realms/celine/partialImport"
        assert json.loads(seen[0].content) == payload

    async def test_group_members_are_read_past_the_first_page(self):
        def handler(request):
            first = int(request.url.params["first"])
            size = int(request.url.params["max"])
            total = 150
            return httpx.Response(200, json=[{"id": f"u{i}"} for i in range(first, min(first + size, total))])

        members = await _client(handler).get_group_members("g-1")

        assert len(members) == 150

    def test_a_user_policy_names_its_users_in_either_shape(self):
        assert KeycloakAdminClient.admin_policy_user_ids({"users": ["a", "b"]}) == {"a", "b"}
        assert KeycloakAdminClient.admin_policy_user_ids({"config": {"users": '["a"]'}}) == {"a"}
        assert KeycloakAdminClient.admin_policy_user_ids({}) == set()

    async def test_a_group_is_created_with_its_attributes(self):
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            if request.method == "POST":
                return httpx.Response(201)
            return httpx.Response(200, json=[{"id": "g-1", "path": MIRROR_GROUP}])

        gid = await _client(handler).create_group_with_attributes("member-mirrors", {MIRROR_MARKER: [SOURCE]})

        assert gid == "g-1"
        assert json.loads(seen[0].content) == {"name": "member-mirrors", "attributes": {MIRROR_MARKER: [SOURCE]}}

    async def test_a_missing_user_reads_as_none(self):
        def handler(request):
            return httpx.Response(404)

        assert await _client(handler).get_user_by_id(SUB_A) is None
        with pytest.raises(KeycloakNotFoundError):
            await _client(handler).get_group("g-1")
