"""`compute_sync_plan` — the diff `keycloak sync` applies to a live realm.

This is the one pure function in the sync path, and everything downstream just
executes what it returns. Both directions of error are expensive: a missing
action leaves a service unable to authenticate, and a spurious one rewrites a
realm that was already correct — which for scope *assignments* means removing a
grant a running service is using.

Two behaviours here are load-bearing and easy to break without noticing:
idempotence (a second run must plan nothing) and orphan scoping (`--prune`
deletes what lands in `orphan_*`, so anything unmanaged that leaks into those
lists is a deletion nobody asked for).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from celine.policies.cli.keycloak.client import CurrentState
from celine.policies.cli.keycloak.models import (
    ClientConfig,
    KeycloakConfig,
    ScopeConfig,
)
from celine.policies.cli.keycloak.sync import (
    SyncResult,
    compute_sync_plan,
    write_secrets_file,
)


def kc_scope(name: str, description: str = "", in_token: bool = True) -> dict:
    """A client scope as the Keycloak admin API returns it."""
    return {
        "id": f"uuid-{name}",
        "name": name,
        "description": description,
        "attributes": {"include.in.token.scope": "true" if in_token else "false"},
    }


def kc_client(
    client_id: str, name: str = "", description: str = "", service_account: bool = True
) -> dict:
    """A client as the Keycloak admin API returns it."""
    return {
        "id": f"uuid-{client_id}",
        "clientId": client_id,
        "name": name or client_id,
        "description": description,
        "serviceAccountsEnabled": service_account,
    }


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------


class TestScopePlanning:
    def test_a_scope_absent_from_keycloak_is_created(self):
        config = KeycloakConfig(scopes=[ScopeConfig(name="dataset.query")])
        plan = compute_sync_plan(config, CurrentState())

        assert [a.scope.name for a in plan.scopes_to_create] == ["dataset.query"]
        assert plan.scopes_to_update == []

    def test_an_identical_scope_is_left_alone(self):
        """Idempotence: the second `sync` of an unchanged file must be a no-op."""
        config = KeycloakConfig(
            scopes=[ScopeConfig(name="dataset.query", description="Query datasets")]
        )
        current = CurrentState(
            scopes={"dataset.query": kc_scope("dataset.query", "Query datasets")}
        )
        plan = compute_sync_plan(config, current)

        assert plan.scopes_to_create == []
        assert plan.scopes_to_update == []
        assert plan.has_changes is False

    def test_a_changed_description_is_an_update(self):
        config = KeycloakConfig(
            scopes=[ScopeConfig(name="dataset.query", description="New wording")]
        )
        current = CurrentState(
            scopes={"dataset.query": kc_scope("dataset.query", "Old wording")}
        )
        plan = compute_sync_plan(config, current)

        assert [a.scope.name for a in plan.scopes_to_update] == ["dataset.query"]
        assert plan.scopes_to_update[0].current is not None

    def test_a_changed_token_inclusion_flag_is_an_update(self):
        """If the scope is not in the token, no policy can ever see it."""
        config = KeycloakConfig(
            scopes=[ScopeConfig(name="dataset.query", include_in_token_scope=False)]
        )
        current = CurrentState(scopes={"dataset.query": kc_scope("dataset.query")})
        plan = compute_sync_plan(config, current)

        assert len(plan.scopes_to_update) == 1

    def test_a_missing_inclusion_attribute_is_read_as_enabled(self):
        """Keycloak omits the attribute when it is at its default of true.

        Reading the absence as false would plan an update on every single run.
        """
        config = KeycloakConfig(scopes=[ScopeConfig(name="dataset.query")])
        current = CurrentState(
            scopes={"dataset.query": {"id": "u", "name": "dataset.query", "description": ""}}
        )
        plan = compute_sync_plan(config, current)

        assert plan.scopes_to_update == []


class TestOrphanScopes:
    def test_a_scope_not_in_the_config_is_an_orphan(self):
        current = CurrentState(scopes={"stale.scope": kc_scope("stale.scope")})
        plan = compute_sync_plan(KeycloakConfig(), current)

        assert plan.orphan_scopes == ["stale.scope"]
        assert plan.has_orphans is True

    def test_orphans_are_not_changes(self):
        """`--prune` is a separate opt-in; a plain sync must report no work."""
        current = CurrentState(scopes={"stale.scope": kc_scope("stale.scope")})
        plan = compute_sync_plan(KeycloakConfig(), current)

        assert plan.has_changes is False
        assert plan.has_orphans is True

    def test_a_managed_prefix_narrows_what_counts_as_an_orphan(self):
        """Realms hold scopes from other tools; `--prune` must not reach them."""
        current = CurrentState(
            scopes={
                "celine.stale": kc_scope("celine.stale"),
                "someone-elses.scope": kc_scope("someone-elses.scope"),
            }
        )
        plan = compute_sync_plan(KeycloakConfig(), current, managed_prefix="celine")

        assert plan.orphan_scopes == ["celine.stale"]


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


class TestClientPlanning:
    def test_a_client_absent_from_keycloak_is_created(self):
        config = KeycloakConfig(clients=[ClientConfig(client_id="svc-x", name="X")])
        plan = compute_sync_plan(config, CurrentState())

        assert [a.client.client_id for a in plan.clients_to_create] == ["svc-x"]

    def test_an_identical_client_is_left_alone(self):
        config = KeycloakConfig(
            clients=[ClientConfig(client_id="svc-x", name="X", description="d")]
        )
        current = CurrentState(clients={"svc-x": kc_client("svc-x", "X", "d")})
        plan = compute_sync_plan(config, current)

        assert plan.clients_to_update == []

    def test_a_changed_name_is_an_update(self):
        config = KeycloakConfig(clients=[ClientConfig(client_id="svc-x", name="New")])
        current = CurrentState(clients={"svc-x": kc_client("svc-x", "Old")})
        plan = compute_sync_plan(config, current)

        assert len(plan.clients_to_update) == 1

    def test_a_changed_description_is_an_update(self):
        config = KeycloakConfig(
            clients=[ClientConfig(client_id="svc-x", name="X", description="new")]
        )
        current = CurrentState(clients={"svc-x": kc_client("svc-x", "X", "old")})
        plan = compute_sync_plan(config, current)

        assert len(plan.clients_to_update) == 1

    def test_a_service_account_being_off_is_an_update(self):
        """Without it there is no client-credentials login at all."""
        config = KeycloakConfig(clients=[ClientConfig(client_id="svc-x", name="X")])
        current = CurrentState(
            clients={"svc-x": kc_client("svc-x", "X", service_account=False)}
        )
        plan = compute_sync_plan(config, current)

        assert len(plan.clients_to_update) == 1

    def test_a_browser_client_keeps_its_service_account_off(self):
        """`svc-ds-portal` is a public client; enabling one would be a regression."""
        config = KeycloakConfig(
            clients=[
                ClientConfig(client_id="svc-portal", name="P", service_account_enabled=False)
            ]
        )
        current = CurrentState(
            clients={"svc-portal": kc_client("svc-portal", "P", service_account=False)}
        )
        plan = compute_sync_plan(config, current)

        assert plan.clients_to_update == []


class TestOrphanClients:
    def test_a_client_not_in_the_config_is_an_orphan(self):
        current = CurrentState(clients={"svc-stale": kc_client("svc-stale")})
        plan = compute_sync_plan(KeycloakConfig(), current)

        assert plan.orphan_clients == ["svc-stale"]

    def test_the_admin_cli_client_is_never_an_orphan(self):
        """`celine-admin-cli` is created by `bootstrap`, not by `clients.yaml`.

        Pruning it would delete the credential the CLI is authenticating with —
        leaving no way to run `sync` again.
        """
        current = CurrentState(clients={"celine-admin-cli": kc_client("celine-admin-cli")})
        plan = compute_sync_plan(KeycloakConfig(), current)

        assert plan.orphan_clients == []

    def test_a_managed_prefix_narrows_orphan_clients(self):
        current = CurrentState(
            clients={
                "svc-stale": kc_client("svc-stale"),
                "grafana": kc_client("grafana"),
            }
        )
        plan = compute_sync_plan(KeycloakConfig(), current, managed_prefix="svc-")

        assert plan.orphan_clients == ["svc-stale"]

    def test_the_oauth2_proxy_client_is_an_orphan_without_a_prefix_guard(self):
        """It is external but reachable by `--prune`, which is worth knowing.

        `oauth2_proxy` is named in `clients.yaml` as `oauth2_proxy_client`, not
        as a managed client, so an unguarded `--prune` would delete the realm's
        entire browser login path. In practice `managed_prefix` guards it; this
        pins the sharp edge rather than pretending it is absent.
        """
        config = KeycloakConfig(oauth2_proxy_client="oauth2_proxy")
        current = CurrentState(clients={"oauth2_proxy": kc_client("oauth2_proxy")})

        assert compute_sync_plan(config, current).orphan_clients == ["oauth2_proxy"]
        assert (
            compute_sync_plan(config, current, managed_prefix="svc-").orphan_clients == []
        )


# ---------------------------------------------------------------------------
# Scope assignments
# ---------------------------------------------------------------------------


class TestScopeAssignments:
    def test_a_new_default_scope_is_assigned(self):
        config = KeycloakConfig(
            clients=[ClientConfig(client_id="svc-x", default_scopes=["dataset.query"])]
        )
        plan = compute_sync_plan(config, CurrentState())

        assert len(plan.scope_assignments_to_add) == 1
        action = plan.scope_assignments_to_add[0]
        assert (action.client_id, action.scope_name, action.assignment_type) == (
            "svc-x",
            "dataset.query",
            "default",
        )

    def test_an_existing_assignment_is_not_repeated(self):
        config = KeycloakConfig(
            clients=[ClientConfig(client_id="svc-x", default_scopes=["dataset.query"])]
        )
        current = CurrentState(client_default_scopes={"svc-x": {"dataset.query"}})
        plan = compute_sync_plan(config, current)

        assert plan.scope_assignments_to_add == []
        assert plan.scope_assignments_to_remove == []

    def test_a_new_optional_scope_is_assigned_as_optional(self):
        config = KeycloakConfig(
            clients=[ClientConfig(client_id="svc-x", optional_scopes=["dataset.query"])]
        )
        plan = compute_sync_plan(config, CurrentState())

        assert plan.scope_assignments_to_add[0].assignment_type == "optional"

    def test_promoting_optional_to_default_removes_the_optional_first(self):
        """Keycloak refuses to hold a scope in both lists, so order matters."""
        config = KeycloakConfig(
            clients=[ClientConfig(client_id="svc-x", default_scopes=["dataset.query"])]
        )
        current = CurrentState(client_optional_scopes={"svc-x": {"dataset.query"}})
        plan = compute_sync_plan(config, current)

        assert [(a.scope_name, a.assignment_type) for a in plan.scope_assignments_to_remove] == [
            ("dataset.query", "optional")
        ]
        assert [(a.scope_name, a.assignment_type) for a in plan.scope_assignments_to_add] == [
            ("dataset.query", "default")
        ]

    def test_demoting_default_to_optional_removes_the_default_first(self):
        config = KeycloakConfig(
            clients=[ClientConfig(client_id="svc-x", optional_scopes=["dataset.query"])]
        )
        current = CurrentState(client_default_scopes={"svc-x": {"dataset.query"}})
        plan = compute_sync_plan(config, current)

        assert [(a.scope_name, a.assignment_type) for a in plan.scope_assignments_to_remove] == [
            ("dataset.query", "default")
        ]
        assert plan.scope_assignments_to_add[0].assignment_type == "optional"

    def test_a_scope_dropped_from_the_config_is_unassigned(self):
        """Revoking a grant is the point; leaving it would make removal impossible."""
        config = KeycloakConfig(clients=[ClientConfig(client_id="svc-x")])
        current = CurrentState(client_default_scopes={"svc-x": {"dataset.admin"}})
        plan = compute_sync_plan(config, current)

        assert [a.scope_name for a in plan.scope_assignments_to_remove] == ["dataset.admin"]

    def test_builtin_scopes_are_never_unassigned(self):
        """`profile`, `roles`, `web-origins` … are realm defaults on every client.

        Stripping them breaks OIDC login itself, and they will never appear in
        `clients.yaml`, so every run would try again.
        """
        config = KeycloakConfig(clients=[ClientConfig(client_id="svc-x")])
        current = CurrentState(
            client_default_scopes={"svc-x": {"profile", "email", "roles", "web-origins"}},
            client_optional_scopes={"svc-x": {"offline_access", "address", "phone"}},
        )
        plan = compute_sync_plan(config, current)

        assert plan.scope_assignments_to_remove == []

    def test_the_scopes_managed_outside_clients_yaml_are_left_assigned(self):
        """`organization`, `groups` and `dataspace` come from `ensure_*` helpers.

        They are provisioned by the claim-scope path, so the diff must treat
        them as built-in rather than tearing them off every client.
        """
        config = KeycloakConfig(clients=[ClientConfig(client_id="svc-x")])
        current = CurrentState(
            client_default_scopes={"svc-x": {"organization", "groups", "dataspace"}}
        )
        plan = compute_sync_plan(config, current)

        assert plan.scope_assignments_to_remove == []

    def test_assignments_are_computed_per_client(self):
        config = KeycloakConfig(
            clients=[
                ClientConfig(client_id="svc-a", default_scopes=["dataset.query"]),
                ClientConfig(client_id="svc-b", default_scopes=["dataset.query"]),
            ]
        )
        current = CurrentState(client_default_scopes={"svc-a": {"dataset.query"}})
        plan = compute_sync_plan(config, current)

        assert [a.client_id for a in plan.scope_assignments_to_add] == ["svc-b"]


# ---------------------------------------------------------------------------
# Audience mappers
# ---------------------------------------------------------------------------


class TestAudienceMappers:
    """`aud` decides whether a callee accepts a caller's token at all.

    A missing mapper is a 401 between two services that are otherwise correctly
    configured — the failure this whole derivation exists to prevent.
    """

    def test_a_foreign_scope_earns_a_mapper_for_its_owner(self):
        config = KeycloakConfig(
            clients=[
                ClientConfig(client_id="svc-dataset-api", scopes_prefix="dataset"),
                ClientConfig(
                    client_id="svc-forecast",
                    scopes_prefix="forecast",
                    default_scopes=["dataset.query"],
                ),
            ]
        )
        plan = compute_sync_plan(config, CurrentState())

        added = {(a.client_id, a.audience_client_id) for a in plan.audience_mappers_to_add}
        assert ("svc-forecast", "svc-dataset-api") in added

    def test_a_client_needs_no_mapper_for_its_own_scopes(self):
        config = KeycloakConfig(
            clients=[
                ClientConfig(
                    client_id="svc-dataset-api",
                    scopes_prefix="dataset",
                    default_scopes=["dataset.query", "dataset.admin"],
                )
            ]
        )
        plan = compute_sync_plan(config, CurrentState())

        assert [
            a for a in plan.audience_mappers_to_add if a.client_id == "svc-dataset-api"
        ] == []

    def test_an_existing_mapper_is_not_recreated(self):
        config = KeycloakConfig(
            clients=[
                ClientConfig(client_id="svc-dataset-api", scopes_prefix="dataset"),
                ClientConfig(
                    client_id="svc-forecast",
                    scopes_prefix="forecast",
                    default_scopes=["dataset.query"],
                ),
            ]
        )
        current = CurrentState(
            client_audience_mappers={"svc-forecast": {"svc-dataset-api": "mapper-1"}}
        )
        plan = compute_sync_plan(config, current)

        assert plan.audience_mappers_to_add == []
        assert plan.audience_mappers_to_remove == []

    def test_a_mapper_for_a_dropped_scope_is_removed_with_its_id(self):
        """The removal call needs the mapper UUID, so it must be carried along."""
        config = KeycloakConfig(
            clients=[ClientConfig(client_id="svc-forecast", scopes_prefix="forecast")]
        )
        current = CurrentState(
            client_audience_mappers={"svc-forecast": {"svc-dataset-api": "mapper-1"}}
        )
        plan = compute_sync_plan(config, current)

        assert len(plan.audience_mappers_to_remove) == 1
        removal = plan.audience_mappers_to_remove[0]
        assert removal.audience_client_id == "svc-dataset-api"
        assert removal.mapper_id == "mapper-1"

    def test_extra_audiences_earn_mappers_for_prefixless_clients(self):
        """A sudo client derives nothing, so this is its only route to an `aud`."""
        config = KeycloakConfig(
            clients=[
                ClientConfig(
                    client_id="celine-cli",
                    default_scopes=["dataset.admin"],
                    extra_audiences=["svc-dataset-api", "oauth2_proxy"],
                )
            ]
        )
        plan = compute_sync_plan(config, CurrentState())

        assert {a.audience_client_id for a in plan.audience_mappers_to_add} == {
            "svc-dataset-api",
            "oauth2_proxy",
        }

    def test_an_unowned_scope_prefix_produces_no_mapper(self):
        """`sync` warns; it must not invent a target from the scope name."""
        config = KeycloakConfig(
            clients=[
                ClientConfig(
                    client_id="svc-forecast",
                    scopes_prefix="forecast",
                    default_scopes=["provenance.write"],
                )
            ]
        )
        plan = compute_sync_plan(config, CurrentState())

        assert plan.audience_mappers_to_add == []


class TestOauth2ProxyMappers:
    """Every service audience has to be in the browser token, or logins 401.

    The proxy client is not managed through `clients.yaml`, so its mappers are
    planned separately — and pruned conservatively.
    """

    @pytest.fixture
    def config(self) -> KeycloakConfig:
        return KeycloakConfig(
            oauth2_proxy_client="oauth2_proxy",
            clients=[
                ClientConfig(client_id="svc-dataset-api", scopes_prefix="dataset"),
                ClientConfig(client_id="svc-forecast", scopes_prefix="forecast"),
                ClientConfig(client_id="celine-cli"),  # no prefix → not a service
            ],
        )

    def test_it_gets_a_mapper_for_every_service_client(self, config: KeycloakConfig):
        plan = compute_sync_plan(config, CurrentState())

        audiences = {
            a.audience_client_id
            for a in plan.audience_mappers_to_add
            if a.client_id == "oauth2_proxy"
        }
        assert {"svc-dataset-api", "svc-forecast"} <= audiences

    def test_it_gets_a_mapper_for_itself(self, config: KeycloakConfig):
        """oauth2-proxy validates `aud` on the token it just received."""
        plan = compute_sync_plan(config, CurrentState())

        audiences = {
            a.audience_client_id
            for a in plan.audience_mappers_to_add
            if a.client_id == "oauth2_proxy"
        }
        assert "oauth2_proxy" in audiences

    def test_a_client_without_a_prefix_gets_no_proxy_mapper(self, config: KeycloakConfig):
        """`celine-cli` is never the audience of a browser token."""
        plan = compute_sync_plan(config, CurrentState())

        audiences = {
            a.audience_client_id
            for a in plan.audience_mappers_to_add
            if a.client_id == "oauth2_proxy"
        }
        assert "celine-cli" not in audiences

    def test_existing_proxy_mappers_are_left_alone(self, config: KeycloakConfig):
        current = CurrentState(
            client_audience_mappers={
                "oauth2_proxy": {
                    "svc-dataset-api": "m1",
                    "svc-forecast": "m2",
                    "oauth2_proxy": "m3",
                }
            }
        )
        plan = compute_sync_plan(config, current)

        assert [a for a in plan.audience_mappers_to_add if a.client_id == "oauth2_proxy"] == []
        assert plan.audience_mappers_to_remove == []

    def test_a_mapper_for_a_retired_service_is_removed(self, config: KeycloakConfig):
        """It is still in `clients.yaml` but no longer a service — drop the `aud`."""
        current = CurrentState(
            client_audience_mappers={"oauth2_proxy": {"celine-cli": "m1"}}
        )
        plan = compute_sync_plan(config, current)

        removals = [
            (a.audience_client_id, a.mapper_id)
            for a in plan.audience_mappers_to_remove
            if a.client_id == "oauth2_proxy"
        ]
        assert removals == [("celine-cli", "m1")]

    def test_a_mapper_pointing_outside_the_config_is_left_in_place(
        self, config: KeycloakConfig
    ):
        """Someone else's realm may need `aud: grafana` on browser tokens.

        Only mappers whose target this file manages are removed — otherwise sync
        would silently break an integration it knows nothing about.
        """
        current = CurrentState(
            client_audience_mappers={"oauth2_proxy": {"grafana": "m-ext"}}
        )
        plan = compute_sync_plan(config, current)

        assert [
            a
            for a in plan.audience_mappers_to_remove
            if a.audience_client_id == "grafana"
        ] == []

    def test_no_proxy_mappers_are_planned_when_none_is_configured(self):
        """A realm without oauth2-proxy must not acquire mappers for one."""
        config = KeycloakConfig(
            clients=[ClientConfig(client_id="svc-dataset-api", scopes_prefix="dataset")]
        )
        plan = compute_sync_plan(config, CurrentState())

        assert [a for a in plan.audience_mappers_to_add if a.client_id == "oauth2_proxy"] == []


# ---------------------------------------------------------------------------
# The shipped config against a realm that already matches it
# ---------------------------------------------------------------------------

CLIENTS_YAML = Path(__file__).resolve().parents[1] / "clients.yaml"


class TestIdempotenceOnTheRealConfig:
    """The property operators rely on: a second `sync` changes nothing.

    A realm is synthesised from `clients.yaml` itself — every scope, client,
    assignment and mapper the plan would create — and then re-diffed. Anything
    planned on that state is a rule that cannot converge, which would show up in
    production as a sync that rewrites the same objects on every run.
    """

    @pytest.fixture
    def config(self) -> KeycloakConfig:
        return KeycloakConfig.from_yaml(CLIENTS_YAML)

    @pytest.fixture
    def realm_in_sync(self, config: KeycloakConfig) -> CurrentState:
        prefix_map = config.build_prefix_to_client_map()
        state = CurrentState(
            scopes={s.name: kc_scope(s.name, s.description) for s in config.scopes},
            clients={
                c.client_id: kc_client(
                    c.client_id, c.name, c.description, c.service_account_enabled
                )
                for c in config.clients
            },
            client_default_scopes={
                c.client_id: set(c.default_scopes) for c in config.clients
            },
            client_optional_scopes={
                c.client_id: set(c.optional_scopes) for c in config.clients
            },
            client_audience_mappers={
                c.client_id: {
                    audience: f"mapper-{c.client_id}-{audience}"
                    for audience in c.desired_audiences(prefix_map)
                }
                for c in config.clients
            },
        )
        proxy = config.oauth2_proxy_client
        if proxy:
            state.clients[proxy] = kc_client(proxy)
            state.client_audience_mappers[proxy] = {
                audience: f"mapper-{proxy}-{audience}"
                for audience in config.get_service_client_ids() | {proxy}
            }
        return state

    def test_nothing_is_planned_against_a_matching_realm(
        self, config: KeycloakConfig, realm_in_sync: CurrentState
    ):
        plan = compute_sync_plan(config, realm_in_sync, managed_prefix="svc-")

        assert plan.summary() == "No changes needed - Keycloak is in sync"
        assert plan.has_changes is False

    def test_an_empty_realm_plans_every_client_and_scope(self, config: KeycloakConfig):
        plan = compute_sync_plan(config, CurrentState())

        assert len(plan.scopes_to_create) == len(config.scopes)
        assert len(plan.clients_to_create) == len(config.clients)
        assert plan.has_orphans is False

    def test_a_pruning_run_on_a_matching_realm_finds_no_orphans(
        self, config: KeycloakConfig, realm_in_sync: CurrentState
    ):
        """With the `svc-` guard, `--prune` on a healthy realm deletes nothing."""
        plan = compute_sync_plan(config, realm_in_sync, managed_prefix="svc-")

        assert plan.orphan_scopes == []
        assert plan.orphan_clients == []


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class TestPlanSummary:
    def test_an_empty_plan_says_so(self):
        assert compute_sync_plan(KeycloakConfig(), CurrentState()).summary() == (
            "No changes needed - Keycloak is in sync"
        )

    def test_every_action_kind_reaches_the_summary(self):
        """`--dry-run` prints only this; an action missing from it is invisible."""
        config = KeycloakConfig(
            oauth2_proxy_client="oauth2_proxy",
            scopes=[ScopeConfig(name="dataset.query", description="d")],
            clients=[
                ClientConfig(client_id="svc-dataset-api", scopes_prefix="dataset"),
                ClientConfig(
                    client_id="svc-forecast",
                    name="Renamed",
                    scopes_prefix="forecast",
                    default_scopes=["dataset.query"],
                    optional_scopes=["forecast.admin"],
                ),
            ],
        )
        current = CurrentState(
            scopes={
                "dataset.query": kc_scope("dataset.query", "old"),
                "stale.scope": kc_scope("stale.scope"),
            },
            clients={
                "svc-forecast": kc_client("svc-forecast", "Old name"),
                "svc-stale": kc_client("svc-stale"),
            },
            client_default_scopes={"svc-forecast": {"dropped.scope"}},
            client_audience_mappers={"svc-forecast": {"svc-gone": "m1"}},
        )
        summary = compute_sync_plan(config, current).summary()

        assert "Scopes to update: 1" in summary
        assert "Clients to create: 1" in summary
        assert "Clients to update: 1" in summary
        assert "Scope assignments to add:" in summary
        assert "Scope assignments to remove:" in summary
        assert "Audience mappers to add:" in summary
        assert "Audience mappers to remove:" in summary
        assert "Orphan scopes" in summary and "stale.scope" in summary
        assert "Orphan clients" in summary and "svc-stale" in summary


class TestSyncResult:
    def test_a_result_without_errors_is_a_success(self):
        assert SyncResult(scopes_created=["a"]).success is True

    def test_any_error_makes_it_a_failure(self):
        """The CLI exits non-zero on this, which is what CI reads."""
        assert SyncResult(errors=["boom"]).success is False

    def test_an_empty_result_reports_no_changes(self):
        assert SyncResult().summary() == "No changes applied"

    def test_errors_are_listed_in_the_summary(self):
        summary = SyncResult(errors=["svc-x: 409 conflict"]).summary()
        assert "Errors: 1" in summary
        assert "svc-x: 409 conflict" in summary


class TestWriteSecretsFile:
    def test_secrets_are_written_in_the_shape_the_cli_reads_back(self, tmp_path: Path):
        """`_load_secret_from_file` parses this file, so the shapes must match.

        A drift between writer and reader turns `bootstrap` into a no-op that
        looks like it worked.
        """
        path = tmp_path / "out.yaml"
        result = SyncResult(
            client_secrets={"svc-x": "secret-x"}, clients_created=["svc-x"]
        )
        write_secrets_file(path, result, KeycloakConfig(realm="celine"))

        data = yaml.safe_load(path.read_text())
        assert data["realm"] == "celine"
        assert data["clients"]["svc-x"]["secret"] == "secret-x"
        assert data["clients"]["svc-x"]["created"] is True
        assert data["clients"]["svc-x"]["updated"] is False

        from celine.policies.cli.keycloak.settings import _load_secret_from_file

        assert _load_secret_from_file(path, "svc-x") == "secret-x"

    def test_it_carries_a_do_not_commit_warning(self, tmp_path: Path):
        """The file holds live credentials and lands in the working tree."""
        path = tmp_path / "out.yaml"
        write_secrets_file(path, SyncResult(), KeycloakConfig())

        assert "DO NOT COMMIT" in path.read_text()

    def test_an_updated_client_is_marked_as_updated(self, tmp_path: Path):
        path = tmp_path / "out.yaml"
        result = SyncResult(
            client_secrets={"svc-x": "s"}, clients_updated=["svc-x"]
        )
        write_secrets_file(path, result, KeycloakConfig())

        data = yaml.safe_load(path.read_text())
        assert data["clients"]["svc-x"]["created"] is False
        assert data["clients"]["svc-x"]["updated"] is True

    def test_it_overwrites_a_previous_file(self, tmp_path: Path):
        """Repeated syncs must not append or leave a stale secret behind."""
        path = tmp_path / "out.yaml"
        write_secrets_file(
            path, SyncResult(client_secrets={"svc-old": "old"}), KeycloakConfig()
        )
        write_secrets_file(
            path, SyncResult(client_secrets={"svc-new": "new"}), KeycloakConfig()
        )

        data = yaml.safe_load(path.read_text())
        assert set(data["clients"]) == {"svc-new"}
