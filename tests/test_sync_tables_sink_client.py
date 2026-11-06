"""`svc-sync-tables-sink` publishes pipeline run events, and nothing else.

A sync_tables sink (`receive --events`) publishes the run events a push carries on its
environment's broker, on `celine/pipelines/runs/<namespace>`, after the push's tables are
committed. The sink is internet-facing (mTLS and a token at its ingress), so its client
holds `pipelines.runs.write` alone: no other scope, no audience of its own, no realm
administration. Its broker token comes from the optional `mqtt` scope that every client
with a topic scope is granted.

Checked over the base file and merged with the ds-host overlay, because an overlay may add
grants to a client.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from celine.sdk.policies import (
    Action,
    PolicyInput,
    Resource,
    ResourceType,
    Subject,
    SubjectType,
)

from celine.policies.cli.keycloak.models import ClientConfig, KeycloakConfig

ROOT = Path(__file__).resolve().parents[1]
CLIENTS_YAML = ROOT / "clients.yaml"
DS_HOST_YAML = ROOT / "clients.ds-host.yaml"

SINK_CLIENT = "svc-sync-tables-sink"
RUNS_WRITE = "pipelines.runs.write"


def _base() -> KeycloakConfig:
    return KeycloakConfig.from_yaml(CLIENTS_YAML)


def _merged() -> KeycloakConfig:
    return KeycloakConfig.from_yaml_files([CLIENTS_YAML, DS_HOST_YAML], complete=False)


def _client(config: KeycloakConfig, client_id: str) -> ClientConfig:
    return next(c for c in config.clients if c.client_id == client_id)


CONFIGS = pytest.mark.parametrize("load", [_base, _merged], ids=["base", "merged"])


@CONFIGS
def test_the_client_holds_runs_write_and_nothing_else(load):
    config = load()
    client = _client(config, SINK_CLIENT)
    held = (set(client.default_scopes) | set(client.optional_scopes)) - {config.broker_scope}

    assert held == {RUNS_WRITE}
    assert RUNS_WRITE in client.default_scopes


@CONFIGS
def test_the_client_administers_nothing_and_owns_nothing(load):
    client = _client(load(), SINK_CLIENT)

    assert not client.realm_management_roles
    assert client.admin_permissions is None or client.admin_permissions.is_empty()
    assert client.scopes_prefix is None
    assert not client.extra_audiences


@CONFIGS
def test_its_token_names_no_gateway_and_no_service(load):
    """The broker checks scopes, and its audience comes from the `mqtt` scope: the client
    adds no audience of its own, so its token reaches no service or gateway."""
    config = load()
    client = _client(config, SINK_CLIENT)

    assert client.desired_audiences(config.build_prefix_to_client_map()) == set()


def test_it_is_granted_the_broker_scope():
    config = _base()
    config.grant_broker_scope()

    assert config.broker_scope in _client(config, SINK_CLIENT).optional_scopes


@pytest.fixture
def acl(policy_engine):
    """The broker's ACL decision for a service holding only the sink client's scope."""

    def _decide(topic: str, action: str) -> bool:
        return policy_engine.evaluate_decision(
            policy_package="celine.mqtt.acl",
            policy_input=PolicyInput(
                subject=Subject(id=SINK_CLIENT, type=SubjectType.SERVICE, scopes=[RUNS_WRITE], groups=[]),
                resource=Resource(type=ResourceType.TOPIC, id=topic),
                action=Action(name=action),
            ),
        ).allowed

    return _decide


def test_it_may_publish_run_events(acl):
    assert acl("celine/pipelines/runs/meters", "publish")


@pytest.mark.parametrize(
    "topic, action",
    [
        ("celine/pipelines/runs/meters", "subscribe"),
        ("celine/flexibility/committed/x", "publish"),
        ("celine/dt/alerts/x", "publish"),
    ],
)
def test_it_may_not_read_runs_or_publish_elsewhere(acl, topic, action):
    assert not acl(topic, action)
