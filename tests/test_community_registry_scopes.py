"""The manager dashboard's registry writes: two optional scopes, and no wider one.

`svc-community` attaches and detaches a member's meter and changes a member's
role and area by writing to the registry with its own token (ADR-0011). Every
registry grant is registry-wide, so what is pinned here is the shape of the
grant: each write is an **optional** scope the BFF requests for that one call,
because the Digital Twin forwards this client's default-scope token to
dataset-api; and `rec-registry.members.write`, which would also rewrite a
member's `user_id`, DID and status, is never held.

Checked over the base file and merged with the ds-host overlay, because an
overlay may add grants to a client.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from celine.policies.cli.keycloak.client import CurrentState
from celine.policies.cli.keycloak.models import ClientConfig, KeycloakConfig
from celine.policies.cli.keycloak.sync import compute_sync_plan

ROOT = Path(__file__).resolve().parents[1]
CLIENTS_YAML = ROOT / "clients.yaml"
DS_HOST_YAML = ROOT / "clients.ds-host.yaml"

COMMUNITY = "svc-community"
ASSETS_WRITE = "rec-registry.assets.write"
PROFILE_WRITE = "rec-registry.members.profile.write"
WRITES = {ASSETS_WRITE, PROFILE_WRITE}


def _base() -> KeycloakConfig:
    return KeycloakConfig.from_yaml(CLIENTS_YAML)


def _merged() -> KeycloakConfig:
    return KeycloakConfig.from_yaml_files([CLIENTS_YAML, DS_HOST_YAML], complete=False)


def _client(config: KeycloakConfig, client_id: str) -> ClientConfig:
    return next(c for c in config.clients if c.client_id == client_id)


CONFIGS = pytest.mark.parametrize("load", [_base, _merged], ids=["base", "merged"])


def test_the_profile_scope_is_declared_in_the_registry_family():
    """@verifies REQ-0005"""
    config = _base()
    declared = {s.name: s for s in config.scopes}

    assert PROFILE_WRITE in declared
    assert declared[PROFILE_WRITE].description
    assert config.build_prefix_to_client_map()["rec-registry"] == "svc-rec-registry"


@CONFIGS
def test_svc_community_holds_both_writes_as_optional_scopes(load):
    """@verifies REQ-0005"""
    community = _client(load(), COMMUNITY)

    assert WRITES <= set(community.optional_scopes)


@CONFIGS
def test_svc_community_default_token_carries_no_registry_write(load):
    """The token the Digital Twin forwards: `rec-registry.read` and nothing
    that writes.

    @verifies REQ-0005
    """
    community = _client(load(), COMMUNITY)

    registry_defaults = {
        s for s in community.default_scopes if s.startswith("rec-registry.")
    }
    assert registry_defaults == {"rec-registry.read"}


@CONFIGS
def test_svc_community_never_holds_members_write_or_admin(load):
    """The narrow scope exists so that the wide one is never needed.

    @verifies REQ-0005
    """
    community = _client(load(), COMMUNITY)
    held = set(community.default_scopes) | set(community.optional_scopes)

    assert "rec-registry.members.write" not in held
    assert "rec-registry.admin" not in held
    assert {s for s in held if s.startswith("rec-registry.")} == {
        "rec-registry.read",
        ASSETS_WRITE,
        PROFILE_WRITE,
    }


def test_a_sync_plans_the_writes_as_optional_assignments():
    """@verifies REQ-0005"""
    plan = compute_sync_plan(_base(), CurrentState())

    assignments = {
        (a.scope_name, a.assignment_type)
        for a in plan.scope_assignments_to_add
        if a.client_id == COMMUNITY and a.scope_name in WRITES
    }
    assert assignments == {(ASSETS_WRITE, "optional"), (PROFILE_WRITE, "optional")}


def test_the_writes_keep_the_audience_onto_the_registry():
    config = _base()
    community = _client(config, COMMUNITY)

    audiences = community.desired_audiences(config.build_prefix_to_client_map())
    assert "svc-rec-registry" in audiences
    assert "svc-provisioning" not in audiences
