"""Onboarding's registry sync: its writes are optional scopes, its reads default.

`svc-onboarding` syncs a community's areas and topology from its onboarding
template into the registry, and sets the community up in the realm first by
calling the provisioning sweep (ADR-0010, ADR-0011). Both are writes a realm
admin starts; neither belongs in the token this client uses for everything else.
So what is pinned here is the shape of the grant: each write is an **optional**
scope onboarding requests for that one call, and the reads the sync and the
console's drift check need are default scopes.

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

ONBOARDING = "svc-onboarding"
COMMUNITY_WRITE = "rec-registry.community.write"
RECONCILE = "provisioning.reconcile"
WRITES = {COMMUNITY_WRITE, RECONCILE}
READS = {"digital-twin.values.read", "rec-registry.read"}


def _base() -> KeycloakConfig:
    return KeycloakConfig.from_yaml(CLIENTS_YAML)


def _merged() -> KeycloakConfig:
    return KeycloakConfig.from_yaml_files([CLIENTS_YAML, DS_HOST_YAML], complete=False)


def _client(config: KeycloakConfig, client_id: str) -> ClientConfig:
    return next(c for c in config.clients if c.client_id == client_id)


CONFIGS = pytest.mark.parametrize("load", [_base, _merged], ids=["base", "merged"])


@CONFIGS
def test_the_sync_writes_are_optional_and_never_default(load):
    """A default-scope token of this client carries no community write and no
    sweep.

    @verifies REQ-0004
    """
    onboarding = _client(load(), ONBOARDING)

    assert WRITES <= set(onboarding.optional_scopes)
    assert not WRITES & set(onboarding.default_scopes)


@CONFIGS
def test_the_reads_are_default_scopes(load):
    """The boundary lookups, and the community reads the sync's dry run, its
    prune count and the drift check make.

    @verifies REQ-0004
    """
    onboarding = _client(load(), ONBOARDING)

    assert READS <= set(onboarding.default_scopes)


@CONFIGS
def test_the_optional_scopes_are_exactly_the_two_writes(load):
    """A third optional scope is a grant somebody has to argue for.

    @verifies REQ-0004
    """
    config = load()
    onboarding = _client(config, ONBOARDING)

    # The broker scope is derived, not argued per client (REQ-0017).
    assert set(onboarding.optional_scopes) - {config.broker_scope} == WRITES


@CONFIGS
def test_nothing_wider_in_the_provisioning_family(load):
    """`participants.write` stays default, `provisioning.admin` stays refused.

    @verifies REQ-0004
    """
    onboarding = _client(load(), ONBOARDING)
    held = set(onboarding.default_scopes) | set(onboarding.optional_scopes)

    assert "provisioning.participants.write" in onboarding.default_scopes
    assert "provisioning.admin" not in held
    assert {s for s in held if s.startswith("provisioning.")} == {
        "provisioning.participants.write",
        RECONCILE,
    }


@CONFIGS
def test_no_registry_scope_that_destroys_a_community(load):
    """The front door never holds the replacement import, the purge or the
    registry-wide admin, as a default or an optional scope."""
    onboarding = _client(load(), ONBOARDING)
    held = set(onboarding.default_scopes) | set(onboarding.optional_scopes)

    assert not held & {
        "rec-registry.import",
        "rec-registry.members.purge",
        "rec-registry.admin",
    }


def test_a_sync_plans_the_writes_as_optional_assignments():
    """@verifies REQ-0004"""
    plan = compute_sync_plan(_base(), CurrentState())

    assignments = {
        (a.scope_name, a.assignment_type)
        for a in plan.scope_assignments_to_add
        if a.client_id == ONBOARDING and a.scope_name in WRITES | READS
    }
    assert assignments == {
        (COMMUNITY_WRITE, "optional"),
        (RECONCILE, "optional"),
        ("rec-registry.read", "default"),
        ("digital-twin.values.read", "default"),
    }


def test_the_new_scopes_add_no_audience():
    """Both writes and the read land on services onboarding already addresses."""
    config = _base()
    onboarding = _client(config, ONBOARDING)

    assert onboarding.desired_audiences(config.build_prefix_to_client_map()) == {
        "svc-digital-twin",
        "svc-provisioning",
        "svc-rec-registry",
    }
