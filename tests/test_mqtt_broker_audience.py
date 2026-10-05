"""REQ-0017: a broker token is a token requested for the broker.

The audience mqtt_auth requires comes from an optional scope, so it is in a token only
when the client asked for it — never in the tokens a service sends over HTTP.
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from celine.policies.cli.keycloak import models
from celine.policies.cli.keycloak.client import (
    AUDIENCE_MAPPER_PREFIX,
    CurrentState,
    KeycloakAdminClient,
)
from celine.policies.cli.keycloak.models import (
    ClientConfig,
    KeycloakConfig,
    MergeError,
    ScopeConfig,
    is_topic_grant_scope,
)
from celine.policies.cli.keycloak.sync import (
    ScopeAction,
    SyncPlan,
    apply_sync_plan,
    compute_sync_plan,
)

CLIENTS_YAML = Path(__file__).resolve().parents[1] / "clients.yaml"


def _config(*clients: ClientConfig) -> KeycloakConfig:
    config = KeycloakConfig(
        broker_scope="mqtt",
        scopes=[ScopeConfig(name="mqtt", audience="svc-mqtt")],
        clients=list(clients),
    )
    config.grant_broker_scope()
    return config


def _scope_with_mapper(audience: str | None) -> dict:
    mappers = []
    if audience:
        mappers.append({
            "id": "m1",
            "name": f"{AUDIENCE_MAPPER_PREFIX}{audience}",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.custom.audience": audience},
        })
    return {"id": "uuid-mqtt", "name": "mqtt", "description": "",
            "attributes": {"include.in.token.scope": "true"}, "protocolMappers": mappers}


# @verifies REQ-0017
@pytest.mark.parametrize("name, grants", [
    ("digital-twin.admin", True),
    ("flexibility.committed.write", True),
    ("pipelines.runs.read", True),
    ("digital-twin.values.*", True),
    ("nudging.ingest", False),
    ("dataset.query", False),
    ("flexibility.commitments.export", False),
    ("mqtt", False),
])
def test_which_scopes_can_grant_a_topic(name, grants):
    """The same shapes `policies/celine/mqtt` turns into a topic grant."""
    assert is_topic_grant_scope(name) is grants


# @verifies REQ-0017
def test_a_service_with_a_topic_scope_gets_the_broker_scope_as_optional():
    config = _config(ClientConfig(client_id="svc-a", default_scopes=["a.events.write"]))
    client = config.clients[0]

    assert "mqtt" in client.optional_scopes
    assert "mqtt" not in client.default_scopes


# @verifies REQ-0017
def test_a_browser_client_or_a_service_without_topic_scopes_does_not():
    config = _config(
        ClientConfig(client_id="login", service_account_enabled=False,
                     default_scopes=["a.events.read"]),
        ClientConfig(client_id="svc-b", default_scopes=["nudging.ingest"]),
    )

    assert all("mqtt" not in c.optional_scopes for c in config.clients)


# @verifies REQ-0017
def test_the_grant_is_idempotent():
    config = _config(ClientConfig(client_id="svc-a", default_scopes=["a.admin"]))

    assert config.grant_broker_scope() == []
    assert config.clients[0].optional_scopes.count("mqtt") == 1


# @verifies REQ-0017
def test_an_undeclared_broker_scope_is_refused():
    config = KeycloakConfig(broker_scope="mqtt", clients=[ClientConfig(client_id="svc-a")])

    with pytest.raises(MergeError, match="names no declared scope"):
        config.grant_broker_scope()


# @verifies REQ-0017
def test_the_shipped_declaration():
    """clients.yaml: the scope carries the audience; services get it, the login client not."""
    config = KeycloakConfig.from_yaml(CLIENTS_YAML)
    scope = next(s for s in config.scopes if s.name == config.broker_scope)
    by_id = {c.client_id: c for c in config.clients}

    assert config.broker_scope == "mqtt"
    assert scope.audience == "svc-mqtt"
    for client_id in ("svc-digital-twin", "svc-flexibility", "svc-grid", "svc-pipelines"):
        assert "mqtt" in by_id[client_id].optional_scopes, client_id
        assert "mqtt" not in by_id[client_id].default_scopes, client_id
    assert "mqtt" not in by_id["oauth2_proxy"].optional_scopes


# A realm declared by two files: the host's, which names the broker, and a guest's,
# whose clients hold scopes shaped like topic grants and never connect to it.
HOST_YAML = """
    realm: celine
    broker_scope: mqtt
    scopes:
      - name: mqtt
        audience: svc-mqtt
      - name: twin.values.write
      - name: twin.admin
      - name: registry.lookup
    clients:
      - client_id: svc-example-twin
        name: Twin
        scopes_prefix: twin
        default_scopes: [twin.admin]
      - client_id: svc-example-http
        name: HTTP only
        default_scopes: [registry.lookup]
"""

GUEST_YAML = """
    scopes:
      - name: connector.provider.read
      - name: identity-registry.memberships.write
    clients:
      - client_id: svc-ds-collector-example
        name: Collector
        default_scopes: [identity-registry.memberships.write]
      - client_id: svc-ds-connector-example
        name: Connector
        scopes_prefix: connector
        default_scopes: [connector.provider.read]
      - client_id: svc-ds-dataset-example
        name: Dataset
        default_scopes: [twin.values.write]
"""

# A host grant on a guest's client: topic-shaped, still not a broker client.
HOST_GRANTS_YAML = """
    clients:
      - client_id: svc-ds-dataset-example
        default_scopes: [twin.admin]
"""


def _realm(tmp_path: Path) -> KeycloakConfig:
    paths = []
    for name, body in (("host.yaml", HOST_YAML), ("grants.yaml", HOST_GRANTS_YAML),
                       ("guest.yaml", GUEST_YAML)):
        path = tmp_path / name
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        paths.append(path)
    return KeycloakConfig.from_yaml_files(paths)


# @verifies REQ-0017
def test_a_guest_client_with_topic_shaped_scopes_gets_no_broker_scope(tmp_path):
    """A ds collector or connector holds `<service>.<resource>.<verb>` scopes for
    HTTP, declared by a file that does not name the broker."""
    by_id = {c.client_id: c for c in _realm(tmp_path).clients}

    for client_id in ("svc-ds-collector-example", "svc-ds-connector-example",
                      "svc-ds-dataset-example"):
        held = set(by_id[client_id].default_scopes) | set(by_id[client_id].optional_scopes)
        assert "mqtt" not in held, client_id


# @verifies REQ-0017
def test_a_broker_service_of_the_declaring_file_still_gets_it(tmp_path):
    by_id = {c.client_id: c for c in _realm(tmp_path).clients}

    assert "mqtt" in by_id["svc-example-twin"].optional_scopes
    assert "mqtt" not in by_id["svc-example-twin"].default_scopes
    assert "mqtt" not in by_id["svc-example-http"].optional_scopes


# @verifies REQ-0017
def test_a_guest_granted_the_broker_scope_by_name_keeps_it(tmp_path):
    """The way a guest that does use the broker gets it: an explicit grant."""
    path = tmp_path / "broker-grant.yaml"
    path.write_text(textwrap.dedent("""
        clients:
          - client_id: svc-ds-connector-example
            optional_scopes: [mqtt]
    """), encoding="utf-8")
    config = _realm(tmp_path)
    merged = KeycloakConfig.from_yaml_files(
        [tmp_path / "host.yaml", tmp_path / "guest.yaml", path]
    )

    assert "mqtt" not in next(
        c for c in config.clients if c.client_id == "svc-ds-connector-example"
    ).optional_scopes
    assert "mqtt" in next(
        c for c in merged.clients if c.client_id == "svc-ds-connector-example"
    ).optional_scopes


# @verifies REQ-0017
def test_one_file_or_no_broker_declaration_has_no_guests(tmp_path):
    host = ("host.yaml", {"broker_scope": "mqtt", "clients": [{"client_id": "a", "name": "A"}]})
    guest = ("guest.yaml", {"clients": [{"client_id": "b", "name": "B"},
                                        {"client_id": "a", "default_scopes": ["x.y.read"]}]})

    assert models.broker_guests([host]) == set()
    assert models.broker_guests([guest]) == set()
    assert models.broker_guests([host, guest]) == {"b"}


# @verifies REQ-0017
def test_the_plan_for_an_existing_realm_removes_the_broker_scope_from_guests_only(tmp_path):
    """A realm synced before the rule: every client holds `mqtt` as optional.

    The plan takes it off the guests and leaves the broker service and the
    scope's audience mapper alone."""
    config = _realm(tmp_path)
    current = CurrentState(
        scopes={"mqtt": _scope_with_mapper("svc-mqtt")},
        client_default_scopes={c.client_id: set(c.default_scopes) for c in config.clients},
        client_optional_scopes={c.client_id: {"mqtt"} for c in config.clients
                                if c.client_id != "svc-example-http"},
    )

    plan = compute_sync_plan(config, current)

    mqtt_changes = sorted(
        (a.client_id, a.assignment_type, a.action)
        for a in plan.scope_assignments_to_add + plan.scope_assignments_to_remove
        if a.scope_name == "mqtt"
    )
    assert mqtt_changes == [
        ("svc-ds-collector-example", "optional", "remove"),
        ("svc-ds-connector-example", "optional", "remove"),
        ("svc-ds-dataset-example", "optional", "remove"),
    ]
    assert all(a.scope.name != "mqtt" for a in plan.scopes_to_update)


# @verifies REQ-0017
@pytest.mark.parametrize("current_audience, updates", [
    (None, True), ("svc-celine-policies", True), ("svc-mqtt", False),
])
def test_the_scope_audience_mapper_is_planned_until_it_matches(current_audience, updates):
    config = KeycloakConfig(scopes=[ScopeConfig(name="mqtt", audience="svc-mqtt")])
    current = CurrentState(scopes={"mqtt": _scope_with_mapper(current_audience)})

    plan = compute_sync_plan(config, current)

    assert bool(plan.scopes_to_update) is updates


@pytest.fixture
def kc() -> MagicMock:
    client = MagicMock(spec=KeycloakAdminClient)
    client.create_client_scope = AsyncMock(return_value="scope-new")
    client.update_client_scope = AsyncMock()
    client.reconcile_scope_audience = AsyncMock(return_value="created")
    return client


# @verifies REQ-0017
async def test_apply_puts_the_audience_on_a_created_and_an_updated_scope(kc):
    plan = SyncPlan(
        scopes_to_create=[ScopeAction(scope=ScopeConfig(name="mqtt-new", audience="svc-mqtt"),
                                      action="create")],
        scopes_to_update=[ScopeAction(scope=ScopeConfig(name="mqtt", audience="svc-mqtt"),
                                      action="update", current=_scope_with_mapper(None))],
    )

    result = await apply_sync_plan(kc, plan, KeycloakConfig(), CurrentState())

    assert result.errors == []
    calls = [c.args for c in kc.reconcile_scope_audience.await_args_list]
    assert calls == [("scope-new", "svc-mqtt"), ("uuid-mqtt", "svc-mqtt")]
