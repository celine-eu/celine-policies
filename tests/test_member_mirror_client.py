"""`svc-member-mirror` reads the mirror export of prod's registry, and nothing else.

The staging member-mirror job (REQ-0021) reads `GET /admin/export/mirror` from prod's
registry through prod's API gateway, with a client-credentials token of prod's realm. Its
client holds `rec-registry.mirror` alone: no other registry action, no realm
administration, no group grant. The token names `svc-rec-registry` (the registry checks
its audience) and `oauth2_proxy` (the gateway accepts a bearer token only with it), as
`svc-pipelines`' does.

Checked over the base file and merged with the ds-host overlay, because an overlay may add
grants to a client.

@verifies REQ-0021
"""

from __future__ import annotations

from pathlib import Path

import pytest

from celine.policies.cli.keycloak.models import ClientConfig, KeycloakConfig

ROOT = Path(__file__).resolve().parents[1]
CLIENTS_YAML = ROOT / "clients.yaml"
DS_HOST_YAML = ROOT / "clients.ds-host.yaml"

MIRROR_CLIENT = "svc-member-mirror"
MIRROR_SCOPE = "rec-registry.mirror"


def _base() -> KeycloakConfig:
    return KeycloakConfig.from_yaml(CLIENTS_YAML)


def _merged() -> KeycloakConfig:
    return KeycloakConfig.from_yaml_files([CLIENTS_YAML, DS_HOST_YAML], complete=False)


def _client(config: KeycloakConfig, client_id: str) -> ClientConfig:
    return next(c for c in config.clients if c.client_id == client_id)


CONFIGS = pytest.mark.parametrize("load", [_base, _merged], ids=["base", "merged"])


@CONFIGS
def test_the_scope_is_declared(load):
    assert MIRROR_SCOPE in {s.name for s in load().scopes}


@CONFIGS
def test_the_client_holds_the_mirror_scope_and_nothing_else(load):
    config = load()
    client = _client(config, MIRROR_CLIENT)
    held = (set(client.default_scopes) | set(client.optional_scopes)) - {config.broker_scope}

    assert held == {MIRROR_SCOPE}
    assert MIRROR_SCOPE in client.default_scopes


@CONFIGS
def test_the_client_administers_nothing(load):
    client = _client(load(), MIRROR_CLIENT)

    assert not client.realm_management_roles
    assert client.admin_permissions is None or client.admin_permissions.is_empty()
    assert client.scopes_prefix is None


@CONFIGS
def test_its_token_names_the_registry_and_the_gateway(load):
    config = load()
    client = _client(config, MIRROR_CLIENT)

    assert client.desired_audiences(config.build_prefix_to_client_map()) == {
        "svc-rec-registry",
        "oauth2_proxy",
    }


@CONFIGS
def test_no_other_client_holds_the_mirror_scope_but_the_admin_superset(load):
    """Only the mirror client is granted it by name; `rec-registry.admin` (celine-cli)
    covers it through the registry's admin override, as it covers every action."""
    holders = {
        c.client_id
        for c in load().clients
        if MIRROR_SCOPE in set(c.default_scopes) | set(c.optional_scopes)
    }

    assert holders == {MIRROR_CLIENT}
