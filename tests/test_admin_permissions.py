"""Declaring what a service account may administer, and the diff that grants it.

`clients.yaml` could say what a client may *ask for* and not what its service
account may *do to the realm*, so the two realm-management roles `svc-onboarding`
needs were granted by hand and a realm rebuilt from the declaration came back
unable to provision logins (celine-policies#2).

What replaced them is not a realm-management role at all. Keycloak 26.6 has
fine-grained admin permissions on by default, so the grant is scoped to the
members of one group: the difference between *may manage participants* and *may
disable an operator*.

Two things here were measured against a real Keycloak 26.6.0 rather than reasoned
about, and the tests exist to keep them from drifting quietly:

- **`manage-members` and `manage-membership` are a pair.** Creating a user in a
  group needs both. Granted either alone, Keycloak accepts the permission with a
  201 and refuses every creation with a 403 — legible only at the far end, as a
  REC operator unable to complete an approval, which is the exact symptom the
  issue was raised about.
- **Only names carrying the managed sentinel are ever touched**, the same
  discipline `AUDIENCE_MAPPER_PREFIX` enforces for mappers. A permission an
  operator made in the console must survive a sync.

The apply path is not covered here; like the rest of this suite, nothing talks to
a Keycloak. See `../.agents` — the store's `playbooks/testing.md`.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from celine.policies.cli.keycloak.client import (
    ADMIN_PERMISSION_PREFIX,
    UNMANAGED_KEYCLOAK_CLIENT_IDS,
    CurrentState,
    GroupAdminGrantState,
    KeycloakAdminClient,
    admin_permission_name,
    admin_policy_name,
)
from celine.policies.cli.keycloak.models import (
    AdminGroupPermission,
    AdminPermissions,
    ClientConfig,
    KeycloakConfig,
    MergeError,
)
from celine.policies.cli.keycloak.sync import compute_sync_plan


def a_client(
    client_id: str = "svc-onboarding",
    groups: list[tuple[str, list[str]]] | None = None,
) -> ClientConfig:
    """A client declaring admin permissions over the given (path, scopes) pairs."""
    return ClientConfig(
        client_id=client_id,
        name=client_id,
        admin_permissions=(
            None
            if groups is None
            else AdminPermissions(
                groups=[
                    AdminGroupPermission(path=path, scopes=scopes)
                    for path, scopes in groups
                ]
            )
        ),
    )


def a_config(*clients: ClientConfig) -> KeycloakConfig:
    return KeycloakConfig(realm="celine", scopes=[], clients=list(clients))


def granted(
    client_id: str, path: str, scopes: set[str], enabled: bool = True
) -> CurrentState:
    """A realm that already grants `client_id` `scopes` over `path`."""
    return CurrentState(
        admin_permissions_enabled=enabled,
        admin_permissions_client_uuid="uuid-admin-permissions",
        admin_group_permissions={
            client_id: {
                path: GroupAdminGrantState(
                    permission_id=f"perm-{client_id}-{path.lstrip('/')}",
                    scopes=set(scopes),
                    group_id=f"gid-{path.lstrip('/')}",
                )
            }
        },
    )


# ---------------------------------------------------------------------------
# The declaration
# ---------------------------------------------------------------------------


class TestDeclaration:
    def test_a_client_declares_nothing_by_default(self):
        assert ClientConfig(client_id="svc-x").admin_permissions is None

    def test_a_client_declaring_no_group_counts_as_declaring_nothing(self):
        config = a_config(a_client(groups=[]))
        assert config.clients_with_admin_permissions() == []

    def test_a_client_declaring_a_group_is_found(self):
        config = a_config(a_client(groups=[("/participants", ["manage-members"])]))
        assert [c.client_id for c in config.clients_with_admin_permissions()] == [
            "svc-onboarding"
        ]

    def test_a_group_path_becomes_a_group_name(self):
        grant = AdminGroupPermission(path="/participants", scopes=["view-members"])
        assert grant.group_name == "participants"


class TestDeclarationIsChecked:
    """Every one of these is a mistake Keycloak accepts and then honours as nothing.

    That is why they are refused at load time rather than left to the API: a
    permission naming a scope Keycloak does not define is created with a 201 and
    grants exactly nothing, so the realm comes back looking configured and
    refusing every call.
    """

    def test_a_scope_keycloak_does_not_define_is_refused(self):
        config = a_config(a_client(groups=[("/participants", ["manage-users"])]))
        problems = config.malformed_admin_permissions()
        assert len(problems) == 1
        assert "manage-users" in problems[0]
        assert "svc-onboarding" in problems[0]

    def test_a_path_without_a_leading_slash_is_refused(self):
        config = a_config(a_client(groups=[("participants", ["view-members"])]))
        assert any("starts with" in p for p in config.malformed_admin_permissions())

    def test_a_nested_path_is_refused(self):
        """Only top-level groups, and an org group is not reachable this way at all."""
        config = a_config(a_client(groups=[("/example_rec/participants", ["view-members"])]))
        assert any(
            "top-level" in p for p in config.malformed_admin_permissions()
        )

    def test_a_grant_of_no_scopes_is_refused(self):
        config = a_config(a_client(groups=[("/participants", [])]))
        assert any("no scope" in p for p in config.malformed_admin_permissions())

    def test_the_same_group_twice_is_refused(self):
        config = a_config(
            a_client(
                groups=[
                    ("/participants", ["view-members"]),
                    ("/participants", ["manage-members"]),
                ]
            )
        )
        assert any("twice" in p for p in config.malformed_admin_permissions())

    def test_a_well_formed_declaration_has_no_problems(self):
        config = a_config(
            a_client(groups=[("/participants", ["manage-members", "manage-membership"])])
        )
        assert config.malformed_admin_permissions() == []

    def test_loading_a_file_with_a_bad_scope_fails_before_anything_is_authenticated(
        self, tmp_path
    ):
        path = tmp_path / "clients.yaml"
        path.write_text(
            "realm: celine\n"
            "clients:\n"
            "  - client_id: svc-onboarding\n"
            "    name: Onboarding\n"
            "    admin_permissions:\n"
            "      groups:\n"
            "        - path: /participants\n"
            "          scopes: [manage-users]\n"
        )
        with pytest.raises(MergeError, match="manage-users"):
            KeycloakConfig.from_yaml(path)


class TestAdminPermissionsAreNotAGrant:
    """A second file may widen what a client asks for, not what it may administer.

    `GRANT_KEYS` is the list of keys a file may carry on a client another file
    declares. Realm administration rights are not on it: a dataspace's overlay
    must not be able to hand a client the ability to manage users in celine's
    realm.
    """

    def test_a_second_file_cannot_add_admin_permissions_to_a_foreign_client(
        self, tmp_path
    ):
        base = tmp_path / "clients.yaml"
        base.write_text(
            "realm: celine\n"
            "clients:\n"
            "  - client_id: svc-onboarding\n"
            "    name: Onboarding\n"
        )
        overlay = tmp_path / "overlay.yaml"
        overlay.write_text(
            "clients:\n"
            "  - client_id: svc-onboarding\n"
            "    admin_permissions:\n"
            "      groups:\n"
            "        - path: /participants\n"
            "          scopes: [manage-members]\n"
        )
        with pytest.raises(MergeError, match="declared by both"):
            KeycloakConfig.from_yaml_files([base, overlay], complete=False)


# ---------------------------------------------------------------------------
# Naming — the sentinel that keeps hand-made permissions out of the plan
# ---------------------------------------------------------------------------


class TestManagedNames:
    def test_a_permission_name_carries_the_sentinel_client_and_group(self):
        name = admin_permission_name("svc-onboarding", "/participants")
        assert name.startswith(ADMIN_PERMISSION_PREFIX)
        assert name == "celine-policies:svc-onboarding:group:participants"

    def test_a_policy_is_named_once_per_client(self):
        assert admin_policy_name("svc-onboarding") == (
            "celine-policies:client:svc-onboarding"
        )

    def test_a_permission_name_round_trips(self):
        name = admin_permission_name("svc-onboarding", "/participants")
        assert KeycloakAdminClient._parse_group_permission_name(name) == (
            "svc-onboarding",
            "/participants",
        )

    def test_a_policy_name_is_not_read_as_a_group_permission(self):
        """Policies share the prefix, so the parser has to reject them."""
        name = admin_policy_name("svc-onboarding")
        assert KeycloakAdminClient._parse_group_permission_name(name) == (None, None)


class TestPolicyClientUuids:
    """Keycloak reports a client policy's clients in two different shapes.

    Fetched on its own it carries `clients` as a list. In a *listing* the same
    policy carries them inside `config` as a JSON-encoded string and omits
    `clients` entirely. Reading only the first shape made every sync conclude the
    policy pointed at the wrong client and rewrite it — which then failed,
    because the `config` block a listing returns is not accepted back on a PUT.
    """

    def test_a_direct_representation_is_read(self):
        policy = {"clients": ["uuid-a"]}
        assert KeycloakAdminClient._policy_client_uuids(policy) == {"uuid-a"}

    def test_a_listing_representation_is_read(self):
        policy = {"config": {"clients": '["uuid-a"]'}}
        assert KeycloakAdminClient._policy_client_uuids(policy) == {"uuid-a"}

    def test_an_unparseable_config_is_empty_rather_than_an_error(self):
        policy = {"config": {"clients": "not json"}}
        assert KeycloakAdminClient._policy_client_uuids(policy) == set()

    def test_a_policy_naming_nobody_is_empty(self):
        assert KeycloakAdminClient._policy_client_uuids({}) == set()


# ---------------------------------------------------------------------------
# The plan
# ---------------------------------------------------------------------------


class TestInertWhenNothingDeclaresIt:
    """The property that makes this safe to ship to realms already in service."""

    def test_no_declaration_plans_nothing_and_leaves_the_realm_flag_alone(self):
        config = a_config(ClientConfig(client_id="svc-x", name="x"))
        # A realm already holding that client, so nothing *else* is planned
        # either and `has_changes` speaks only about admin permissions.
        current = CurrentState(
            clients={
                "svc-x": {
                    "id": "uuid-svc-x",
                    "clientId": "svc-x",
                    "name": "x",
                    "description": "",
                    "serviceAccountsEnabled": True,
                }
            }
        )
        plan = compute_sync_plan(config, current)

        assert plan.enable_admin_permissions is False
        assert plan.admin_permissions_to_add == []
        assert plan.admin_permissions_to_update == []
        assert plan.admin_permissions_to_remove == []
        assert plan.has_changes is False

    def test_the_realm_flag_is_not_turned_on_for_a_declaration_of_no_groups(self):
        plan = compute_sync_plan(a_config(a_client(groups=[])), CurrentState())
        assert plan.enable_admin_permissions is False


class TestPlanningTheGrant:
    def test_a_declared_grant_absent_from_the_realm_is_added(self):
        config = a_config(
            a_client(groups=[("/participants", ["manage-members", "view-members"])])
        )
        plan = compute_sync_plan(config, CurrentState())

        assert len(plan.admin_permissions_to_add) == 1
        action = plan.admin_permissions_to_add[0]
        assert action.client_id == "svc-onboarding"
        assert action.group_path == "/participants"
        assert action.scopes == ["manage-members", "view-members"]

    def test_a_realm_without_the_feature_on_is_turned_on(self):
        config = a_config(a_client(groups=[("/participants", ["view-members"])]))
        plan = compute_sync_plan(config, CurrentState(admin_permissions_enabled=False))
        assert plan.enable_admin_permissions is True

    def test_a_realm_already_enabled_is_left_alone(self):
        config = a_config(a_client(groups=[("/participants", ["view-members"])]))
        current = granted("svc-onboarding", "/participants", {"view-members"})
        plan = compute_sync_plan(config, current)
        assert plan.enable_admin_permissions is False

    def test_an_identical_grant_plans_nothing(self):
        """Idempotence: a second run must plan no admin-permission action."""
        config = a_config(
            a_client(groups=[("/participants", ["manage-members", "view-members"])])
        )
        current = granted(
            "svc-onboarding", "/participants", {"manage-members", "view-members"}
        )
        plan = compute_sync_plan(config, current)

        assert plan.admin_permissions_to_add == []
        assert plan.admin_permissions_to_update == []
        assert plan.admin_permissions_to_remove == []

    def test_the_declared_order_of_scopes_does_not_matter(self):
        config = a_config(
            a_client(groups=[("/participants", ["view-members", "manage-members"])])
        )
        current = granted(
            "svc-onboarding", "/participants", {"manage-members", "view-members"}
        )
        assert compute_sync_plan(config, current).admin_permissions_to_update == []

    def test_a_widened_grant_is_an_update(self):
        config = a_config(
            a_client(
                groups=[("/participants", ["manage-members", "manage-membership"])]
            )
        )
        current = granted("svc-onboarding", "/participants", {"manage-members"})
        plan = compute_sync_plan(config, current)

        assert len(plan.admin_permissions_to_update) == 1
        action = plan.admin_permissions_to_update[0]
        assert action.current_scopes == {"manage-members"}
        assert action.scopes == ["manage-members", "manage-membership"]
        assert action.permission_id == "perm-svc-onboarding-participants"

    def test_a_narrowed_grant_is_an_update(self):
        """Drift in the widening direction is repaired too, not only shortfalls."""
        config = a_config(a_client(groups=[("/participants", ["view-members"])]))
        current = granted(
            "svc-onboarding",
            "/participants",
            {"manage-members", "manage-membership", "view-members"},
        )
        plan = compute_sync_plan(config, current)

        assert len(plan.admin_permissions_to_update) == 1
        assert plan.admin_permissions_to_update[0].scopes == ["view-members"]


class TestRevoking:
    """The issue's requirement: a grant removed from the file comes off the realm.

    Without this the drift simply returns in the other direction — the realm
    keeps a rights grant nothing declares, and nothing says so.
    """

    def test_a_group_dropped_from_the_declaration_is_revoked(self):
        config = a_config(a_client(groups=[("/participants", ["view-members"])]))
        current = granted("svc-onboarding", "/contractors", {"manage-members"})
        plan = compute_sync_plan(config, current)

        assert len(plan.admin_permissions_to_remove) == 1
        action = plan.admin_permissions_to_remove[0]
        assert action.group_path == "/contractors"
        assert action.current_scopes == {"manage-members"}

    def test_a_client_dropping_the_block_entirely_still_has_its_grant_revoked(self):
        """The case that is easy to miss.

        Such a client is not in `clients_with_admin_permissions()` at all, so a
        revocation derived from the declaration would never look at it. It is
        derived from what the realm holds instead.
        """
        config = a_config(a_client(groups=None))
        current = granted("svc-onboarding", "/participants", {"manage-members"})
        plan = compute_sync_plan(config, current)

        assert len(plan.admin_permissions_to_remove) == 1
        assert plan.admin_permissions_to_remove[0].group_path == "/participants"

    def test_revoking_counts_as_a_change_so_it_is_not_skipped(self):
        config = a_config(a_client(groups=None))
        current = granted("svc-onboarding", "/participants", {"manage-members"})
        assert compute_sync_plan(config, current).has_changes is True


class TestTheScopePairing:
    """`manage-members` without `manage-membership` cannot create anybody.

    Measured on 26.6.0 — neither scope alone gets past a `POST /users` carrying a
    `groups` entry, and the pair does. It is not refused, because administering
    members that already exist is a legitimate narrower grant; it is warned
    about, because the failure surfaces a long way from the file that caused it.
    """

    def test_managing_members_without_membership_warns(self, caplog):
        config = a_config(a_client(groups=[("/participants", ["manage-members"])]))
        with caplog.at_level(logging.WARNING):
            compute_sync_plan(config, CurrentState())
        assert "manage-membership" in caplog.text
        assert "/participants" in caplog.text

    def test_the_pair_together_does_not_warn(self, caplog):
        config = a_config(
            a_client(
                groups=[("/participants", ["manage-members", "manage-membership"])]
            )
        )
        with caplog.at_level(logging.WARNING):
            compute_sync_plan(config, CurrentState())
        assert "manage-membership" not in caplog.text

    def test_a_read_only_grant_does_not_warn(self):
        config = a_config(a_client(groups=[("/participants", ["view-members"])]))
        plan = compute_sync_plan(config, CurrentState())
        assert len(plan.admin_permissions_to_add) == 1


class TestFindingTheGroupNeedsView:
    """The member scopes cannot resolve the group they administer.

    Measured on 26.6.0: holding `manage-members` + `manage-membership` +
    `view-members` and nothing else, *every* route to the group's id answers 403
    — `group-by-path`, `GET /groups?search=`, and `GET /groups/{id}` on the very
    group being administered. Adding `view` opens `group-by-path` and
    `GET /groups/{id}`; `GET /groups` stays 403, because listing the realm's
    groups is a realm-wide act.

    Every member call is addressed by that id, so the grant this repository first
    shipped could create a participant and never find one again. Warned rather
    than refused, for the same reason the pairing is: a permission whose scopes
    are all member-addressed is a coherent narrower grant, and the warning names
    what will break.
    """

    def test_member_scopes_without_view_warn(self, caplog):
        config = a_config(
            a_client(
                groups=[
                    (
                        "/participants",
                        ["manage-members", "manage-membership", "view-members"],
                    )
                ]
            )
        )
        with caplog.at_level(logging.WARNING):
            compute_sync_plan(config, CurrentState())

        assert "'view'" in caplog.text
        assert "/participants" in caplog.text

    def test_view_alongside_them_does_not_warn(self, caplog):
        config = a_config(
            a_client(
                groups=[
                    (
                        "/participants",
                        [
                            "manage-members",
                            "manage-membership",
                            "view-members",
                            "view",
                        ],
                    )
                ]
            )
        )
        with caplog.at_level(logging.WARNING):
            compute_sync_plan(config, CurrentState())

        assert caplog.text == ""

    def test_a_lone_member_scope_warns_too(self, caplog):
        """`view-members` alone is just as unable to name the group."""
        config = a_config(a_client(groups=[("/participants", ["view-members"])]))
        with caplog.at_level(logging.WARNING):
            compute_sync_plan(config, CurrentState())

        assert "'view'" in caplog.text

    def test_a_grant_of_view_alone_does_not_warn(self, caplog):
        """Nothing member-addressed is declared, so nothing is unreachable."""
        config = a_config(a_client(groups=[("/participants", ["view"])]))
        with caplog.at_level(logging.WARNING):
            compute_sync_plan(config, CurrentState())

        assert caplog.text == ""

    def test_it_warns_and_still_plans_the_grant(self):
        """A warning is not a refusal — the declaration is still applied."""
        config = a_config(a_client(groups=[("/participants", ["view-members"])]))
        plan = compute_sync_plan(config, CurrentState())

        assert len(plan.admin_permissions_to_add) == 1


class TestTwoClientsOnOneGroupAreRefused:
    """A second client granted the same group revokes the first one silently.

    Measured on 26.6.0: with a permission for `svc-a` and another for `svc-b` on
    `/participants`, *both* clients get 403 on everything — creating, reading
    members, resolving the group. The admin-permissions resource server decides
    `UNANIMOUS` and so does each permission, so a permission whose client policy
    does not name you votes against you.

    Keycloak refuses none of it: both permissions are created with a 201. So the
    refusal is here, at load time, before anything is authenticated — the same
    place an unknown scope name is caught, and for the same reason.
    """

    def test_two_clients_declaring_one_group_is_refused(self):
        config = a_config(
            a_client("svc-a", groups=[("/participants", ["view-members", "view"])]),
            a_client("svc-b", groups=[("/participants", ["view-members", "view"])]),
        )
        problems = config.malformed_admin_permissions()

        assert len(problems) == 1
        assert "/participants" in problems[0]

    def test_the_refusal_names_both_clients(self):
        """The operator has to know which declaration to remove."""
        config = a_config(
            a_client("svc-a", groups=[("/participants", ["view"])]),
            a_client("svc-b", groups=[("/participants", ["view"])]),
        )
        problem = config.malformed_admin_permissions()[0]

        assert "svc-a" in problem
        assert "svc-b" in problem

    def test_it_says_the_second_declaration_breaks_the_first(self):
        """Naming the consequence, because the API reports none."""
        config = a_config(
            a_client("svc-a", groups=[("/participants", ["view"])]),
            a_client("svc-b", groups=[("/participants", ["view"])]),
        )
        problem = config.malformed_admin_permissions()[0]

        assert "deny each other" in problem

    def test_three_clients_on_one_group_is_one_problem_naming_all_three(self):
        config = a_config(
            a_client("svc-a", groups=[("/participants", ["view"])]),
            a_client("svc-b", groups=[("/participants", ["view"])]),
            a_client("svc-c", groups=[("/participants", ["view"])]),
        )
        problems = config.malformed_admin_permissions()

        assert len(problems) == 1
        assert all(c in problems[0] for c in ("svc-a", "svc-b", "svc-c"))

    def test_different_groups_for_different_clients_are_fine(self):
        """The conflict is one group, not the feature. Measured: no interference."""
        config = a_config(
            a_client("svc-a", groups=[("/participants", ["view"])]),
            a_client("svc-b", groups=[("/operators", ["view"])]),
        )

        assert config.malformed_admin_permissions() == []

    def test_one_client_declaring_two_groups_is_fine(self):
        config = a_config(
            a_client(
                "svc-a",
                groups=[("/participants", ["view"]), ("/operators", ["view"])],
            )
        )

        assert config.malformed_admin_permissions() == []

    def test_loading_a_conflicting_file_fails_before_anything_is_authenticated(
        self, tmp_path: Path
    ):
        """The whole point of a load-time check: no realm is touched."""
        path = tmp_path / "clients.yaml"
        path.write_text(
            "realm: celine\n"
            "scopes: []\n"
            "clients:\n"
            "  - client_id: svc-a\n"
            "    name: A\n"
            "    admin_permissions:\n"
            "      groups:\n"
            "        - path: /participants\n"
            "          scopes: [view]\n"
            "  - client_id: svc-b\n"
            "    name: B\n"
            "    admin_permissions:\n"
            "      groups:\n"
            "        - path: /participants\n"
            "          scopes: [view]\n"
        )

        with pytest.raises(ValueError, match="deny each other"):
            KeycloakConfig.from_yaml(path)


class TestTheGroupsParticipantsAreFiledIn:
    """`sync-users` reads the same declaration `sync` grants from.

    A group declared as administered and empty of everything this tool creates is
    a grant over nobody: onboarding attempts a create, gets `409 User exists with
    same username`, scans the group and does not find the account. So the paths
    come from one place, and the two commands cannot name different groups.
    """

    def test_a_declared_group_is_reported_with_its_client(self):
        config = a_config(
            a_client("svc-onboarding", groups=[("/participants", ["view"])])
        )

        assert config.admin_permission_group_paths() == {
            "/participants": ["svc-onboarding"]
        }

    def test_a_configuration_declaring_nothing_names_no_group(self):
        """What keeps `sync-users` unchanged for everyone not using the feature."""
        assert a_config(a_client(groups=None)).admin_permission_group_paths() == {}

    def test_an_empty_block_names_no_group(self):
        assert a_config(a_client(groups=[])).admin_permission_group_paths() == {}

    def test_every_declared_group_is_named(self):
        config = a_config(
            a_client("svc-a", groups=[("/participants", ["view"])]),
            a_client("svc-b", groups=[("/operators", ["view"])]),
        )

        assert sorted(config.admin_permission_group_paths()) == [
            "/operators",
            "/participants",
        ]

    def test_the_real_declaration_names_the_participants_group(self):
        config = KeycloakConfig.from_yaml(Path("clients.yaml"))

        assert config.admin_permission_group_paths() == {
            "/participants": ["svc-onboarding"]
        }


class TestTheRealmsOwnClientIsNotAnOrphan:
    """`--prune` must never delete the resource server holding the permissions.

    Keycloak creates `admin-permissions` when the feature is enabled. It is not
    declared in `clients.yaml`, so without an explicit exemption it lands in
    `orphan_clients` — where `--prune` would delete it, and every permission
    with it. Exactly the trap `oauth2_proxy` is already pinned against.
    """

    def test_it_is_filtered_out_of_the_current_state(self):
        assert "admin-permissions" in UNMANAGED_KEYCLOAK_CLIENT_IDS

    def test_the_other_keycloak_owned_clients_are_still_filtered(self):
        """The exemption was widened, not replaced."""
        assert {
            "admin-cli",
            "broker",
            "realm-management",
            "security-admin-console",
        } <= UNMANAGED_KEYCLOAK_CLIENT_IDS


# ---------------------------------------------------------------------------
# The declaration as it actually ships
# ---------------------------------------------------------------------------


class TestTheRealDeclaration:
    def test_svc_onboarding_may_administer_participants_and_nothing_else(self):
        config = KeycloakConfig.from_yaml(Path("clients.yaml"))
        declaring = config.clients_with_admin_permissions()

        assert [c.client_id for c in declaring] == ["svc-onboarding"]

        grants = declaring[0].admin_permissions.groups
        assert [g.path for g in grants] == ["/participants"]

    def test_it_carries_the_pair_creation_needs(self):
        config = KeycloakConfig.from_yaml(Path("clients.yaml"))
        scopes = set(
            config.clients_with_admin_permissions()[0].admin_permissions.groups[0].scopes
        )
        assert {"manage-members", "manage-membership"} <= scopes

    def test_it_carries_view_so_the_grant_can_find_its_group(self):
        """Without it the service creates participants and finds none of them."""
        config = KeycloakConfig.from_yaml(Path("clients.yaml"))
        scopes = set(
            config.clients_with_admin_permissions()[0].admin_permissions.groups[0].scopes
        )
        assert "view" in scopes

    def test_the_shipped_declaration_warns_about_no_half_grant(self, caplog):
        """Neither half-grant. The unrelated `oauth2_proxy` audience warning is
        pre-existing and not what this asserts about."""
        config = KeycloakConfig.from_yaml(Path("clients.yaml"))
        with caplog.at_level(logging.WARNING):
            compute_sync_plan(config, CurrentState())

        assert "/participants" not in caplog.text

    def test_nothing_in_the_declaration_is_malformed(self):
        config = KeycloakConfig.from_yaml(Path("clients.yaml"))
        assert config.malformed_admin_permissions() == []

