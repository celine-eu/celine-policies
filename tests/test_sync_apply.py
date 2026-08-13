"""`apply_sync_plan` — the write half of `keycloak sync`, against a mocked realm.

The plan says what should change; this executes it. Three properties are what an
operator actually relies on, and none of them are visible from the plan alone:

*Dry-run writes nothing.* `--dry-run` is what people run against production
before the real thing. It must report the same actions while issuing no calls —
a single write leaking past a `dry_run` guard makes the flag a lie.

*Deletion needs `--prune`.* Orphans are reported by every run; they may only be
deleted when explicitly asked for.

*One failure does not abandon the rest.* Errors are collected into `SyncResult`,
so a 403 on one client still leaves the other eighteen configured. Raising
instead would leave the realm half-synced at whatever object failed first.

The client is a mock: what matters here is which calls are made, in what order,
and what happens when one of them fails.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from celine.policies.cli.keycloak.client import (
    CurrentState,
    KeycloakAdminClient,
    KeycloakConflictError,
    KeycloakNotFoundError,
)
from celine.policies.cli.keycloak.models import (
    ClientConfig,
    KeycloakConfig,
    ScopeConfig,
)
from celine.policies.cli.keycloak.sync import (
    AudienceMapperAction,
    ClientAction,
    ScopeAction,
    ScopeAssignmentAction,
    SyncPlan,
    apply_sync_plan,
)

# Every method apply_sync_plan may call to *change* something. Dry-run asserts
# that none of these were awaited.
WRITE_METHODS = [
    "create_client_scope",
    "update_client_scope",
    "delete_client_scope",
    "create_client",
    "update_client",
    "delete_client",
    "add_client_default_scope",
    "add_client_optional_scope",
    "remove_client_default_scope",
    "remove_client_optional_scope",
    "create_audience_mapper",
    "delete_protocol_mapper",
]


@pytest.fixture
def kc() -> MagicMock:
    """A Keycloak admin client that records calls instead of making them."""
    client = MagicMock(spec=KeycloakAdminClient)
    client.create_client_scope = AsyncMock(return_value="scope-new")
    client.update_client_scope = AsyncMock()
    client.delete_client_scope = AsyncMock()
    client.create_client = AsyncMock(return_value=("uuid-new", "secret-new"))
    client.update_client = AsyncMock()
    client.delete_client = AsyncMock()
    client.get_client_secret = AsyncMock(return_value="secret-existing")
    client.get_client_by_client_id = AsyncMock(return_value=None)
    client.get_client_scope_by_name = AsyncMock(return_value=None)
    client.list_client_scopes = AsyncMock(return_value=[])
    client.add_client_default_scope = AsyncMock()
    client.add_client_optional_scope = AsyncMock()
    client.remove_client_default_scope = AsyncMock()
    client.remove_client_optional_scope = AsyncMock()
    client.create_audience_mapper = AsyncMock(return_value="mapper-new")
    client.delete_protocol_mapper = AsyncMock()
    return client


def full_plan() -> SyncPlan:
    """A plan touching every branch: create, update, assign, map, orphan."""
    return SyncPlan(
        scopes_to_create=[ScopeAction(scope=ScopeConfig(name="new.scope"), action="create")],
        scopes_to_update=[
            ScopeAction(
                scope=ScopeConfig(name="old.scope"),
                action="update",
                current={"id": "scope-old"},
            )
        ],
        clients_to_create=[
            ClientAction(client=ClientConfig(client_id="svc-new"), action="create")
        ],
        clients_to_update=[
            ClientAction(
                client=ClientConfig(client_id="svc-old"),
                action="update",
                current={"id": "uuid-old"},
            )
        ],
        scope_assignments_to_add=[
            ScopeAssignmentAction(
                client_id="svc-old",
                scope_name="old.scope",
                assignment_type="default",
                action="add",
            )
        ],
        scope_assignments_to_remove=[
            ScopeAssignmentAction(
                client_id="svc-old",
                scope_name="stale.scope",
                assignment_type="optional",
                action="remove",
            )
        ],
        audience_mappers_to_add=[
            AudienceMapperAction(
                client_id="svc-old", audience_client_id="svc-dataset-api", action="add"
            )
        ],
        audience_mappers_to_remove=[
            AudienceMapperAction(
                client_id="svc-old",
                audience_client_id="svc-gone",
                action="remove",
                mapper_id="mapper-1",
            )
        ],
        orphan_scopes=["orphan.scope"],
        orphan_clients=["svc-orphan"],
    )


def full_state() -> CurrentState:
    """The realm those actions resolve against — UUIDs for everything existing."""
    return CurrentState(
        scopes={
            "old.scope": {"id": "scope-old", "name": "old.scope"},
            "stale.scope": {"id": "scope-stale", "name": "stale.scope"},
            "orphan.scope": {"id": "scope-orphan", "name": "orphan.scope"},
        },
        clients={
            "svc-old": {"id": "uuid-old", "clientId": "svc-old"},
            "svc-orphan": {"id": "uuid-orphan", "clientId": "svc-orphan"},
        },
    )


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


class TestDryRun:
    async def test_no_write_is_issued(self, kc: MagicMock):
        result = await apply_sync_plan(
            kc, full_plan(), KeycloakConfig(), full_state(), prune=True, dry_run=True
        )

        for method in WRITE_METHODS:
            assert not getattr(kc, method).await_args_list, f"{method} was called"
        assert result.success is True

    async def test_the_same_actions_are_reported(self, kc: MagicMock):
        """`--dry-run` output is what the operator reads before running for real.

        If it under-reported, the real run would apply changes nobody previewed.
        """
        result = await apply_sync_plan(
            kc, full_plan(), KeycloakConfig(), full_state(), prune=True, dry_run=True
        )

        assert result.scopes_created == ["new.scope"]
        assert result.scopes_updated == ["old.scope"]
        assert result.clients_created == ["svc-new"]
        assert result.clients_updated == ["svc-old"]
        assert result.scope_assignments_added == [("svc-old", "old.scope", "default")]
        assert result.scope_assignments_removed == [
            ("svc-old", "stale.scope", "optional")
        ]
        assert result.audience_mappers_added == [("svc-old", "svc-dataset-api")]
        assert result.audience_mappers_removed == [("svc-old", "svc-gone")]

    async def test_orphans_are_reported_only_with_prune(self, kc: MagicMock):
        without = await apply_sync_plan(
            kc, full_plan(), KeycloakConfig(), full_state(), prune=False, dry_run=True
        )
        with_prune = await apply_sync_plan(
            kc, full_plan(), KeycloakConfig(), full_state(), prune=True, dry_run=True
        )

        assert without.clients_deleted == []
        assert without.scopes_deleted == []
        assert with_prune.clients_deleted == ["svc-orphan"]
        assert with_prune.scopes_deleted == ["orphan.scope"]

    async def test_no_secret_is_invented(self, kc: MagicMock):
        """A dry run must not write a secrets file full of fictional credentials."""
        result = await apply_sync_plan(
            kc, full_plan(), KeycloakConfig(), full_state(), dry_run=True
        )

        assert result.client_secrets == {}


# ---------------------------------------------------------------------------
# Applying for real
# ---------------------------------------------------------------------------


class TestScopeApplication:
    async def test_a_new_scope_is_created_with_its_settings(self, kc: MagicMock):
        plan = SyncPlan(
            scopes_to_create=[
                ScopeAction(
                    scope=ScopeConfig(
                        name="new.scope",
                        description="d",
                        include_in_token_scope=False,
                    ),
                    action="create",
                )
            ]
        )
        result = await apply_sync_plan(kc, plan, KeycloakConfig(), CurrentState())

        kc.create_client_scope.assert_awaited_once()
        assert kc.create_client_scope.await_args.kwargs["name"] == "new.scope"
        assert kc.create_client_scope.await_args.kwargs["include_in_token_scope"] is False
        assert result.scopes_created == ["new.scope"]

    async def test_a_conflict_on_create_recovers_the_existing_id(self, kc: MagicMock):
        """Two syncs racing, or a scope created by hand between plan and apply.

        The id is needed by the assignment step that follows, so the conflict is
        resolved rather than recorded as an error.
        """
        kc.create_client_scope = AsyncMock(side_effect=KeycloakConflictError("409"))
        kc.get_client_scope_by_name = AsyncMock(return_value={"id": "scope-existing"})
        plan = SyncPlan(
            scopes_to_create=[
                ScopeAction(scope=ScopeConfig(name="new.scope"), action="create")
            ],
            scope_assignments_to_add=[
                ScopeAssignmentAction(
                    client_id="svc-old",
                    scope_name="new.scope",
                    assignment_type="default",
                    action="add",
                )
            ],
        )
        state = CurrentState(clients={"svc-old": {"id": "uuid-old"}})

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        assert result.errors == []
        kc.add_client_default_scope.assert_awaited_once_with("uuid-old", "scope-existing")

    async def test_a_failure_to_create_is_recorded_not_raised(self, kc: MagicMock):
        kc.create_client_scope = AsyncMock(side_effect=RuntimeError("boom"))
        plan = SyncPlan(
            scopes_to_create=[
                ScopeAction(scope=ScopeConfig(name="a.scope"), action="create"),
                ScopeAction(scope=ScopeConfig(name="b.scope"), action="create"),
            ]
        )

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), CurrentState())

        assert result.success is False
        assert len(result.errors) == 2, "the second scope was still attempted"

    async def test_an_update_uses_the_id_from_the_current_state(self, kc: MagicMock):
        plan = SyncPlan(
            scopes_to_update=[
                ScopeAction(
                    scope=ScopeConfig(name="old.scope"),
                    action="update",
                    current={"id": "scope-old"},
                )
            ]
        )

        await apply_sync_plan(kc, plan, KeycloakConfig(), CurrentState())

        assert kc.update_client_scope.await_args.kwargs["scope_id"] == "scope-old"


class TestClientApplication:
    async def test_a_created_clients_secret_is_captured(self, kc: MagicMock):
        """It is the only moment the secret is available to write to disk."""
        plan = SyncPlan(
            clients_to_create=[
                ClientAction(client=ClientConfig(client_id="svc-new"), action="create")
            ]
        )

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), CurrentState())

        assert result.client_secrets == {"svc-new": "secret-new"}

    async def test_an_updated_clients_secret_is_read_back(self, kc: MagicMock):
        """The secrets file must stay complete across runs, not only on creation."""
        plan = SyncPlan(
            clients_to_update=[
                ClientAction(
                    client=ClientConfig(client_id="svc-old"),
                    action="update",
                    current={"id": "uuid-old"},
                )
            ]
        )

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), CurrentState())

        assert result.client_secrets == {"svc-old": "secret-existing"}

    async def test_a_conflict_on_create_recovers_the_uuid_and_secret(self, kc: MagicMock):
        kc.create_client = AsyncMock(side_effect=KeycloakConflictError("409"))
        kc.get_client_by_client_id = AsyncMock(return_value={"id": "uuid-existing"})
        plan = SyncPlan(
            clients_to_create=[
                ClientAction(client=ClientConfig(client_id="svc-new"), action="create")
            ]
        )

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), CurrentState())

        assert result.errors == []
        assert result.client_secrets == {"svc-new": "secret-existing"}

    async def test_a_failure_is_recorded_with_the_client_id(self, kc: MagicMock):
        kc.create_client = AsyncMock(side_effect=RuntimeError("403 forbidden"))
        plan = SyncPlan(
            clients_to_create=[
                ClientAction(client=ClientConfig(client_id="svc-new"), action="create")
            ]
        )

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), CurrentState())

        assert result.success is False
        assert "svc-new" in result.errors[0]


class TestScopeAssignmentApplication:
    @pytest.fixture
    def state(self) -> CurrentState:
        return CurrentState(
            clients={"svc-x": {"id": "uuid-x"}},
            scopes={"dataset.query": {"id": "scope-q"}},
        )

    async def test_a_default_assignment_calls_the_default_endpoint(
        self, kc: MagicMock, state: CurrentState
    ):
        plan = SyncPlan(
            scope_assignments_to_add=[
                ScopeAssignmentAction(
                    client_id="svc-x",
                    scope_name="dataset.query",
                    assignment_type="default",
                    action="add",
                )
            ]
        )

        await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        kc.add_client_default_scope.assert_awaited_once_with("uuid-x", "scope-q")
        kc.add_client_optional_scope.assert_not_awaited()

    async def test_an_optional_assignment_calls_the_optional_endpoint(
        self, kc: MagicMock, state: CurrentState
    ):
        plan = SyncPlan(
            scope_assignments_to_add=[
                ScopeAssignmentAction(
                    client_id="svc-x",
                    scope_name="dataset.query",
                    assignment_type="optional",
                    action="add",
                )
            ]
        )

        await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        kc.add_client_optional_scope.assert_awaited_once_with("uuid-x", "scope-q")

    async def test_builtin_scope_ids_are_resolved_by_listing(self, kc: MagicMock):
        """`profile` and friends are never in `current.scopes` — they are filtered.

        Assigning one still needs its id, so the scope list is re-read first.
        """
        kc.list_client_scopes = AsyncMock(
            return_value=[{"name": "profile", "id": "scope-profile"}]
        )
        plan = SyncPlan(
            scope_assignments_to_add=[
                ScopeAssignmentAction(
                    client_id="svc-x",
                    scope_name="profile",
                    assignment_type="default",
                    action="add",
                )
            ]
        )
        state = CurrentState(clients={"svc-x": {"id": "uuid-x"}})

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        kc.add_client_default_scope.assert_awaited_once_with("uuid-x", "scope-profile")
        assert result.errors == []

    async def test_an_unresolvable_scope_is_an_error(self, kc: MagicMock):
        """Silently skipping would leave a service one grant short, quietly."""
        plan = SyncPlan(
            scope_assignments_to_add=[
                ScopeAssignmentAction(
                    client_id="svc-x",
                    scope_name="ghost.scope",
                    assignment_type="default",
                    action="add",
                )
            ]
        )
        state = CurrentState(clients={"svc-x": {"id": "uuid-x"}})

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        assert result.success is False
        assert "ghost.scope" in result.errors[0]

    async def test_removing_an_already_absent_assignment_is_not_an_error(
        self, kc: MagicMock, state: CurrentState
    ):
        """Converging on the desired state; it is already there."""
        kc.remove_client_default_scope = AsyncMock(side_effect=KeycloakNotFoundError("404"))
        plan = SyncPlan(
            scope_assignments_to_remove=[
                ScopeAssignmentAction(
                    client_id="svc-x",
                    scope_name="dataset.query",
                    assignment_type="default",
                    action="remove",
                )
            ]
        )

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        assert result.errors == []

    async def test_an_unknown_client_is_skipped_without_erroring(self, kc: MagicMock):
        plan = SyncPlan(
            scope_assignments_to_add=[
                ScopeAssignmentAction(
                    client_id="svc-ghost",
                    scope_name="dataset.query",
                    assignment_type="default",
                    action="add",
                )
            ]
        )

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), CurrentState())

        kc.add_client_default_scope.assert_not_awaited()
        assert result.scope_assignments_added == []


class TestAudienceMapperApplication:
    @pytest.fixture
    def state(self) -> CurrentState:
        return CurrentState(clients={"svc-x": {"id": "uuid-x"}})

    async def test_a_mapper_is_created_on_the_requesting_client(
        self, kc: MagicMock, state: CurrentState
    ):
        plan = SyncPlan(
            audience_mappers_to_add=[
                AudienceMapperAction(
                    client_id="svc-x", audience_client_id="svc-dataset-api", action="add"
                )
            ]
        )

        await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        kc.create_audience_mapper.assert_awaited_once_with(
            client_uuid="uuid-x", audience_client_id="svc-dataset-api"
        )

    async def test_a_removal_uses_the_mapper_id_from_the_plan(
        self, kc: MagicMock, state: CurrentState
    ):
        plan = SyncPlan(
            audience_mappers_to_remove=[
                AudienceMapperAction(
                    client_id="svc-x",
                    audience_client_id="svc-gone",
                    action="remove",
                    mapper_id="mapper-7",
                )
            ]
        )

        await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        kc.delete_protocol_mapper.assert_awaited_once_with(
            client_uuid="uuid-x", mapper_id="mapper-7"
        )

    async def test_a_removal_without_an_id_deletes_nothing(
        self, kc: MagicMock, state: CurrentState
    ):
        """Guessing which mapper was meant could delete an unrelated one."""
        plan = SyncPlan(
            audience_mappers_to_remove=[
                AudienceMapperAction(
                    client_id="svc-x",
                    audience_client_id="svc-gone",
                    action="remove",
                    mapper_id=None,
                )
            ]
        )

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        kc.delete_protocol_mapper.assert_not_awaited()
        assert result.audience_mappers_removed == []

    async def test_a_mapper_already_gone_is_not_an_error(
        self, kc: MagicMock, state: CurrentState
    ):
        kc.delete_protocol_mapper = AsyncMock(side_effect=KeycloakNotFoundError("404"))
        plan = SyncPlan(
            audience_mappers_to_remove=[
                AudienceMapperAction(
                    client_id="svc-x",
                    audience_client_id="svc-gone",
                    action="remove",
                    mapper_id="mapper-7",
                )
            ]
        )

        result = await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        assert result.errors == []


class TestPruning:
    async def test_nothing_is_deleted_without_prune(self, kc: MagicMock):
        result = await apply_sync_plan(
            kc, full_plan(), KeycloakConfig(), full_state(), prune=False
        )

        kc.delete_client.assert_not_awaited()
        kc.delete_client_scope.assert_not_awaited()
        assert result.clients_deleted == []
        assert result.scopes_deleted == []

    async def test_prune_deletes_orphan_clients_and_scopes(self, kc: MagicMock):
        result = await apply_sync_plan(
            kc, full_plan(), KeycloakConfig(), full_state(), prune=True
        )

        kc.delete_client.assert_awaited_once_with("uuid-orphan")
        kc.delete_client_scope.assert_awaited_once_with("scope-orphan")
        assert result.clients_deleted == ["svc-orphan"]
        assert result.scopes_deleted == ["orphan.scope"]

    async def test_an_orphan_with_no_known_uuid_is_skipped(self, kc: MagicMock):
        plan = SyncPlan(orphan_clients=["svc-ghost"], orphan_scopes=["ghost.scope"])

        result = await apply_sync_plan(
            kc, plan, KeycloakConfig(), CurrentState(), prune=True
        )

        kc.delete_client.assert_not_awaited()
        assert result.clients_deleted == []

    async def test_a_failed_deletion_is_recorded(self, kc: MagicMock):
        kc.delete_client = AsyncMock(side_effect=RuntimeError("in use"))

        result = await apply_sync_plan(
            kc, full_plan(), KeycloakConfig(), full_state(), prune=True
        )

        assert any("svc-orphan" in e for e in result.errors)


class TestOrdering:
    """Sequencing is not cosmetic — several steps depend on earlier ones.

    Scopes must exist before they are assigned, and an assignment being moved
    between the default and optional lists must be removed before it is re-added
    or Keycloak rejects it.
    """

    async def test_scopes_are_created_before_they_are_assigned(self, kc: MagicMock):
        calls: list[str] = []
        kc.create_client_scope = AsyncMock(
            side_effect=lambda **_: calls.append("create-scope") or "scope-new"
        )
        kc.add_client_default_scope = AsyncMock(
            side_effect=lambda *_: calls.append("assign")
        )
        plan = SyncPlan(
            scopes_to_create=[
                ScopeAction(scope=ScopeConfig(name="new.scope"), action="create")
            ],
            scope_assignments_to_add=[
                ScopeAssignmentAction(
                    client_id="svc-x",
                    scope_name="new.scope",
                    assignment_type="default",
                    action="add",
                )
            ],
        )
        state = CurrentState(clients={"svc-x": {"id": "uuid-x"}})

        await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        assert calls == ["create-scope", "assign"]

    async def test_a_client_is_created_before_its_mapper(self, kc: MagicMock):
        calls: list[str] = []
        kc.create_client = AsyncMock(
            side_effect=lambda **_: calls.append("create-client")
            or ("uuid-new", "secret-new")
        )
        kc.create_audience_mapper = AsyncMock(
            side_effect=lambda **_: calls.append("mapper") or "m"
        )
        plan = SyncPlan(
            clients_to_create=[
                ClientAction(client=ClientConfig(client_id="svc-new"), action="create")
            ],
            audience_mappers_to_add=[
                AudienceMapperAction(
                    client_id="svc-new",
                    audience_client_id="svc-dataset-api",
                    action="add",
                )
            ],
        )

        await apply_sync_plan(kc, plan, KeycloakConfig(), CurrentState())

        assert calls == ["create-client", "mapper"]

    async def test_an_assignment_is_removed_before_it_is_re_added(self, kc: MagicMock):
        """The optional→default move the plan emits as a remove plus an add."""
        calls: list[str] = []
        kc.remove_client_optional_scope = AsyncMock(
            side_effect=lambda *_: calls.append("remove-optional")
        )
        kc.add_client_default_scope = AsyncMock(
            side_effect=lambda *_: calls.append("add-default")
        )
        plan = SyncPlan(
            scope_assignments_to_remove=[
                ScopeAssignmentAction(
                    client_id="svc-x",
                    scope_name="dataset.query",
                    assignment_type="optional",
                    action="remove",
                )
            ],
            scope_assignments_to_add=[
                ScopeAssignmentAction(
                    client_id="svc-x",
                    scope_name="dataset.query",
                    assignment_type="default",
                    action="add",
                )
            ],
        )
        state = CurrentState(
            clients={"svc-x": {"id": "uuid-x"}},
            scopes={"dataset.query": {"id": "scope-q"}},
        )

        await apply_sync_plan(kc, plan, KeycloakConfig(), state)

        assert calls == ["remove-optional", "add-default"]


class TestEmptyPlan:
    async def test_an_empty_plan_changes_nothing(self, kc: MagicMock):
        """The steady state: `sync` on an already-correct realm.

        The scope listing is still read (it is how builtin ids are resolved), but
        nothing is written.
        """
        result = await apply_sync_plan(kc, SyncPlan(), KeycloakConfig(), CurrentState())

        for method in WRITE_METHODS:
            assert not getattr(kc, method).await_args_list, f"{method} was called"
        assert result.success is True
        assert result.summary() == "No changes applied"
