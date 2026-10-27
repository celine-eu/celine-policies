"""`svc-pipelines` reads two exports, and its token passes the API gateway.

The warehouse pipelines mirror the registry (`GET /admin/export`) and the
flexibility commitments (`GET /api/commitments/export`) with this client's
client-credentials token. In a deployment whose warehouse runs on another site,
that token is minted by the site that owns the data and reaches its services
through the public API gateway, `api.<domain>`, where oauth2-proxy checks every
request (`skip_jwt_bearer_tokens`). oauth2-proxy accepts a bearer token only when
its `aud` names oauth2-proxy's own client, so the client lists `oauth2_proxy`
under `extra_audiences`, as `celine-cli` does.

What is pinned here is that the client stays a reader: the two export grants,
its own pipeline-run scopes, and no write on the registry or the commitments.
Checked over the base file and merged with the ds-host overlay, because an
overlay may add grants to a client.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from celine.policies.cli.keycloak.models import ClientConfig, KeycloakConfig

ROOT = Path(__file__).resolve().parents[1]
CLIENTS_YAML = ROOT / "clients.yaml"
DS_HOST_YAML = ROOT / "clients.ds-host.yaml"

PIPELINES = "svc-pipelines"
GATEWAY_AUDIENCE = "oauth2_proxy"
EXPORTS = {"rec-registry.export", "flexibility.commitments.export"}


def _base() -> KeycloakConfig:
    return KeycloakConfig.from_yaml(CLIENTS_YAML)


def _merged() -> KeycloakConfig:
    return KeycloakConfig.from_yaml_files([CLIENTS_YAML, DS_HOST_YAML], complete=False)


def _client(config: KeycloakConfig, client_id: str) -> ClientConfig:
    return next(c for c in config.clients if c.client_id == client_id)


def _scopes(client: ClientConfig) -> set[str]:
    return set(client.default_scopes) | set(client.optional_scopes)


CONFIGS = pytest.mark.parametrize("load", [_base, _merged], ids=["base", "merged"])


@CONFIGS
def test_svc_pipelines_holds_both_exports(load):
    client = _client(load(), PIPELINES)

    assert EXPORTS <= set(client.default_scopes)


@CONFIGS
def test_svc_pipelines_writes_nothing_outside_its_own_runs(load):
    """Registry and flexibility: the two exports and nothing else.

    The broker scope is left out: it only asks for an MQTT token and grants nothing.
    """
    config = load()
    client = _client(config, PIPELINES)
    foreign = {
        s
        for s in _scopes(client)
        if not s.startswith("pipelines.") and s != config.broker_scope
    }

    assert foreign == EXPORTS


@CONFIGS
def test_svc_pipelines_token_names_the_gateway(load):
    """Its token carries `aud: oauth2_proxy`, so oauth2-proxy lets it through."""
    config = load()
    client = _client(config, PIPELINES)
    audiences = client.desired_audiences(config.build_prefix_to_client_map())

    assert GATEWAY_AUDIENCE in client.extra_audiences
    assert {GATEWAY_AUDIENCE, "svc-rec-registry", "svc-flexibility"} <= audiences
