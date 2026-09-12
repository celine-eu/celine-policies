"""Declaring realm-wide administration, which ADR-0003 refused and ADR-0007 adds.

The refusal was right about the reach and is not softened here: every role in
this field is realm-wide, `manage-users` reaches every account in the realm, and
`manage-realm` carries the Organizations API. What changed is the holder — a
service with no public route can hold a coarse grant, and the public front door
never could — so the tests below are mostly about the ways this field must stay
hard to use by accident:

- exactly one client declares it, and `sync` names that client rather than
  counting it;
- a role this Keycloak does not offer stops the sync before it writes anything,
  the treatment ADR-0002 gives an undeclared scope;
- it is additive, and no diff can be read as a revocation.

Nothing here talks to a Keycloak. The plan is computed against a `CurrentState`
built by hand, so what is covered is what `sync` decides, not what Keycloak
accepts — see the store's `playbooks/testing.md`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from celine.policies.cli.keycloak.client import CurrentState
from celine.policies.cli.keycloak.models import ClientConfig, KeycloakConfig, MergeError
from celine.policies.cli.keycloak.sync import compute_sync_plan

ALL_ROLES = {
    "manage-users",
    "manage-realm",
    "view-users",
    "view-realm",
    "manage-clients",
    "view-clients",
    "query-users",
    "query-groups",
    "realm-admin",
}


def a_client(client_id: str = "svc-provisioning", roles: list[str] | None = None):
    return ClientConfig(
        client_id=client_id,
        name=client_id,
        realm_management_roles=roles or [],
    )


def a_config(*clients: ClientConfig) -> KeycloakConfig:
    return KeycloakConfig(realm="celine", scopes=[], clients=list(clients))


def a_state(held: dict[str, set[str]] | None = None) -> CurrentState:
    state = CurrentState()
    state.available_realm_management_roles = set(ALL_ROLES)
    state.realm_management_roles = dict(held or {})
    return state


# --- the default is nothing ----------------------------------------------


def test_a_client_declaring_nothing_administers_nothing():
    """Absent is the default and the only safe one."""
    config = a_config(a_client(roles=None))

    assert config.clients_with_realm_management_roles() == []
    assert compute_sync_plan(config, a_state()).realm_management_roles_to_grant == []


def test_a_realm_that_uses_none_plans_none_and_is_not_consulted():
    """`fetch_realm_management_role_state` is not even called for such a
    declaration, so `available_realm_management_roles` is empty — which must not
    be read as "no role exists"."""
    config = a_config(ClientConfig(client_id="svc-grid", name="svc-grid"))

    plan = compute_sync_plan(config, CurrentState())

    assert plan.realm_management_roles_to_grant == []


# --- granting -------------------------------------------------------------


def test_the_declared_roles_are_granted_to_an_account_holding_none():
    plan = compute_sync_plan(
        a_config(a_client(roles=["manage-users", "manage-realm"])), a_state()
    )

    assert len(plan.realm_management_roles_to_grant) == 1
    action = plan.realm_management_roles_to_grant[0]
    assert action.client_id == "svc-provisioning"
    assert action.roles == ["manage-users", "manage-realm"]
    assert plan.has_changes


def test_only_the_missing_half_is_granted():
    plan = compute_sync_plan(
        a_config(a_client(roles=["manage-users", "manage-realm"])),
        a_state({"svc-provisioning": {"manage-users"}}),
    )

    action = plan.realm_management_roles_to_grant[0]
    assert action.roles == ["manage-realm"]
    assert action.held == {"manage-users"}


def test_a_second_run_plans_nothing():
    plan = compute_sync_plan(
        a_config(a_client(roles=["manage-users", "manage-realm"])),
        a_state({"svc-provisioning": {"manage-users", "manage-realm"}}),
    )

    assert plan.realm_management_roles_to_grant == []


def test_a_role_the_declaration_does_not_name_is_left_alone():
    """Additive. Nothing here can tell a role this tool granted from one an
    operator granted by hand, so a diff is never read as a revocation — there is
    no remove action to produce."""
    plan = compute_sync_plan(
        a_config(a_client(roles=["manage-users"])),
        a_state({"svc-provisioning": {"manage-users", "realm-admin"}}),
    )

    assert plan.realm_management_roles_to_grant == []
    assert not hasattr(plan, "realm_management_roles_to_revoke")


def test_dropping_the_field_revokes_nothing():
    """Removing the declaration is not how realm administration is taken away.
    Somebody has to do it where it can be seen."""
    plan = compute_sync_plan(
        a_config(a_client(roles=[])),
        a_state({"svc-provisioning": {"manage-users", "manage-realm"}}),
    )

    assert plan.realm_management_roles_to_grant == []


# --- refusing what cannot work -------------------------------------------


def test_a_role_keycloak_does_not_have_stops_the_sync():
    """ADR-0002's treatment of an undeclared scope, for the same reason: the
    alternative is a realm that syncs clean and answers 403 to the one call the
    client exists to make."""
    with pytest.raises(ValueError) as excinfo:
        compute_sync_plan(a_config(a_client(roles=["manage-userz"])), a_state())

    message = str(excinfo.value)
    assert "manage-userz" in message
    assert "svc-provisioning" in message
    # and it says what is available, because the next question is always "then
    # what is it called"
    assert "manage-users" in message


def test_the_refusal_names_every_offender_not_only_the_first():
    config = a_config(
        a_client("svc-provisioning", ["manage-users", "nonsense"]),
        a_client("svc-other", ["alsowrong"]),
    )

    with pytest.raises(ValueError) as excinfo:
        compute_sync_plan(config, a_state())

    message = str(excinfo.value)
    assert "nonsense" in message and "alsowrong" in message
    assert "svc-other" in message


# --- it is not a grant a second file may hand out -------------------------


def test_a_second_file_cannot_add_realm_administration_to_a_client(tmp_path: Path):
    """`realm_management_roles` is not in GRANT_KEYS, so an overlay naming it is
    claiming to own the client — which is a merge error, not a widening."""
    base = tmp_path / "base.yaml"
    base.write_text(
        "realm: celine\n"
        "scopes: []\n"
        "clients:\n"
        "  - client_id: svc-grid\n"
        "    name: Grid\n"
    )
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text(
        "clients:\n"
        "  - client_id: svc-grid\n"
        "    realm_management_roles: [manage-users]\n"
    )

    with pytest.raises(MergeError):
        KeycloakConfig.from_yaml_files([base, overlay])


# --- what the real declaration says --------------------------------------


def test_exactly_one_client_in_clients_yaml_holds_realm_administration():
    """The count is the review surface. A second name appearing in this diff is
    the thing somebody has to argue for."""
    config = KeycloakConfig.from_yaml(Path("clients.yaml"))

    holders = config.clients_with_realm_management_roles()

    assert [c.client_id for c in holders] == ["svc-provisioning"]
    assert holders[0].realm_management_roles == ["manage-users", "manage-realm"]


def test_the_provisioning_service_does_not_hold_the_realm_admin_composite():
    """`realm-admin` also carries client and identity-provider administration
    this service never performs. `sync` does that, as a CLI, with an operator's
    credential."""
    config = KeycloakConfig.from_yaml(Path("clients.yaml"))
    holder = config.clients_with_realm_management_roles()[0]

    assert "realm-admin" not in holder.realm_management_roles


def test_the_provisioning_service_cannot_write_to_the_registry():
    """It reconciles Keycloak *from* the registry. `rec-registry.export` and
    nothing else — `.admin` would satisfy `.import`, a replacement import that
    deletes a community with every member in it."""
    config = KeycloakConfig.from_yaml(Path("clients.yaml"))
    client = next(c for c in config.clients if c.client_id == "svc-provisioning")

    registry_scopes = [
        s for s in client.default_scopes if s.startswith("rec-registry.")
    ]
    assert registry_scopes == ["rec-registry.export"]


# --- the posture as a whole ----------------------------------------------


def test_the_declaration_holds_exactly_one_realm_administrator():
    """Two hold Keycloak administration and only one is declarable here —
    `celine-admin-cli` is created by `bootstrap` and deliberately absent, because
    `sync` runs as it.

    `svc-onboarding`'s group-scoped grant over `/participants` is **gone**:
    svc-provisioning took the job over, so the public onboarding front door holds
    no Keycloak right at all.

    The count is the review surface. A second holder is a change somebody has to
    argue for, and this is what makes it fail rather than pass unnoticed."""
    config = KeycloakConfig.from_yaml(Path("clients.yaml"))

    group_scoped = [c.client_id for c in config.clients_with_admin_permissions()]
    realm_wide = [c.client_id for c in config.clients_with_realm_management_roles()]

    assert group_scoped == []
    assert realm_wide == ["svc-provisioning"]


def test_the_admin_cli_client_is_never_an_orphan():
    """`sync` authenticates as `celine-admin-cli` and `clients.yaml` does not
    declare it, which is exactly the shape of an orphan. Pruning it deletes the
    credential the pruning run is using."""
    from celine.policies.cli.keycloak.client import CurrentState
    from celine.policies.cli.keycloak.settings import DEFAULT_ADMIN_CLIENT_ID

    config = KeycloakConfig.from_yaml(Path("clients.yaml"))
    current = CurrentState()
    for client_id in [DEFAULT_ADMIN_CLIENT_ID, "something-nobody-declared"]:
        current.clients[client_id] = {"id": f"uuid-{client_id}", "clientId": client_id}

    plan = compute_sync_plan(config, current)

    assert DEFAULT_ADMIN_CLIENT_ID not in plan.orphan_clients
    assert "something-nobody-declared" in plan.orphan_clients


def test_onboarding_can_call_the_provisioning_service_before_it_does():
    """The scope is granted ahead of the cutover so that switch is a code change
    in `../onboarding` rather than a realm change in the same breath. The
    audience mapper onto svc-provisioning is derived from it."""
    config = KeycloakConfig.from_yaml(Path("clients.yaml"))
    onboarding = next(c for c in config.clients if c.client_id == "svc-onboarding")

    assert "provisioning.participants.write" in onboarding.default_scopes
    assert "svc-provisioning" in onboarding.desired_audiences(
        config.build_prefix_to_client_map()
    )
