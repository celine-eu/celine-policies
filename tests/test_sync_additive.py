"""`keycloak sync --additive` — add and update, and take nothing away.

A run without the flag converges: whatever the merged files no longer name is
removed from the clients they declare. That is safe only when every run is handed
the complete file set, and an init container handed a narrower one (a missing
overlay, a stale mount) narrows live clients on every restart. `--additive`
applies every create and update, applies no removal, and reports each removal it
held back, so the operator still reads what a full run would take away.

Each test names, in its docstring, the change that turns it red. The filter lives
in one place, `hold_back_removals`, and the helper below runs the same sequence
the command does: plan, filter, apply.

The client is a mock, as in `test_sync_apply.py`; nothing here talks to Keycloak.
`tests/integration/test_additive_sync.py` is the live counterpart.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from typer.testing import CliRunner

from celine.policies.cli.keycloak.client import (
    ClaimMapperState,
    CurrentState,
    GroupAdminGrantState,
    KeycloakAdminClient,
)
from celine.policies.cli.keycloak.models import (
    AdminGroupPermission,
    AdminPermissions,
    ClientConfig,
    KeycloakConfig,
    ScopeConfig,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.policies.cli.keycloak.sync import (
    SyncResult,
    apply_sync_plan,
    compute_sync_plan,
    hold_back_removals,
)
from celine.policies.cli.main import app

# Every method apply_sync_plan may call to change something, the admin
# permission path included.
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
    "create_hardcoded_claim_mapper",
    "update_hardcoded_claim_mapper",
    "delete_protocol_mapper",
    "delete_admin_permission",
    "create_group_admin_permission",
    "update_group_admin_permission",
    "ensure_group",
    "ensure_admin_client_policy",
]

#: The removal methods: none of these may be awaited by an additive run.
REMOVAL_METHODS = [
    "remove_client_default_scope",
    "remove_client_optional_scope",
    "delete_protocol_mapper",
    "delete_admin_permission",
    "delete_client",
    "delete_client_scope",
]


@pytest.fixture
def kc() -> MagicMock:
    client = MagicMock(spec=KeycloakAdminClient)
    for method in WRITE_METHODS:
        setattr(client, method, AsyncMock())
    client.create_client_scope.return_value = "scope-new"
    client.create_client.return_value = ("uuid-new", "secret-new")
    client.ensure_group.return_value = ("gid-new", False)
    client.ensure_admin_client_policy.return_value = "policy-1"
    client.get_client_secret = AsyncMock(return_value="secret-existing")
    client.get_client_by_client_id = AsyncMock(return_value=None)
    client.get_client_scope_by_name = AsyncMock(return_value=None)
    client.list_client_scopes = AsyncMock(return_value=[])
    return client


def awaited(kc: MagicMock, *methods: str) -> dict[str, int]:
    return {m: getattr(kc, m).await_count for m in methods if getattr(kc, m).await_count}


async def run(kc, config, current, additive=True, dry_run=False):
    """The command's sequence: plan, filter when additive, apply."""
    plan = compute_sync_plan(config, current)
    held = None
    if additive:
        plan, held = hold_back_removals(plan)
    result = await apply_sync_plan(kc, plan, config, current, dry_run=dry_run)
    if held is not None:
        result.held_back = held.lines()
    return plan, held, result


# A realm with one declared client holding more than the files grant it.
SCOPES = [ScopeConfig(name="alpha.read"), ScopeConfig(name="alpha.write")]


def svc(**kw) -> ClientConfig:
    kw.setdefault("client_id", "svc-alpha")
    kw.setdefault("name", kw["client_id"])
    return ClientConfig(**kw)


def realm(**kw) -> CurrentState:
    """svc-alpha exists; scopes exist; everything else as given."""
    base = dict(
        scopes={
            "alpha.read": {"id": "sid-read", "name": "alpha.read"},
            "alpha.write": {"id": "sid-write", "name": "alpha.write"},
            "hand.made": {"id": "sid-hand", "name": "hand.made"},
        },
        clients={
            "svc-alpha": {
                "id": "uuid-alpha",
                "clientId": "svc-alpha",
                "name": "svc-alpha",
                "serviceAccountsEnabled": True,
            }
        },
    )
    base.update(kw)
    return CurrentState(**base)


# ---------------------------------------------------------------------------
# Scope assignments
# ---------------------------------------------------------------------------


class TestScopeAssignmentsAreKept:
    async def test_t1_an_undeclared_default_scope_stays(self, kc):
        """T1. *Red:* `hold_back_removals` returns the plan unfiltered — the
        remove call is observed."""
        config = KeycloakConfig(scopes=SCOPES, clients=[svc(default_scopes=["alpha.read"])])
        current = realm(client_default_scopes={"svc-alpha": {"alpha.read", "hand.made"}})

        _, held, result = await run(kc, config, current)

        kc.remove_client_default_scope.assert_not_awaited()
        assert result.scope_assignments_removed == []
        assert "  = svc-alpha <- hand.made (default)" in result.held_back

    async def test_t2_an_undeclared_optional_scope_stays(self, kc):
        """T2. *Red:* hold back only `assignment_type="default"` removals."""
        config = KeycloakConfig(scopes=SCOPES, clients=[svc(optional_scopes=["alpha.read"])])
        current = realm(client_optional_scopes={"svc-alpha": {"alpha.read", "hand.made"}})

        _, _, result = await run(kc, config, current)

        kc.remove_client_optional_scope.assert_not_awaited()
        assert "  = svc-alpha <- hand.made (optional)" in result.held_back

    async def test_without_the_flag_the_same_scope_is_removed(self, kc):
        """The counterpart that proves the scenario above really plans a removal."""
        config = KeycloakConfig(scopes=SCOPES, clients=[svc(default_scopes=["alpha.read"])])
        current = realm(client_default_scopes={"svc-alpha": {"alpha.read", "hand.made"}})

        await run(kc, config, current, additive=False)

        kc.remove_client_default_scope.assert_awaited_once_with("uuid-alpha", "sid-hand")


class TestADefaultOptionalMoveIsHeldWhole:
    """Question 2, answered the safer way: both halves are held back."""

    def config_and_realm(self):
        # Declared optional, held as default by the realm.
        config = KeycloakConfig(scopes=SCOPES, clients=[svc(optional_scopes=["alpha.write"])])
        current = realm(client_default_scopes={"svc-alpha": {"alpha.write"}})
        return config, current

    async def test_t10_neither_half_is_applied(self, kc):
        """T10. *Red:* hold back only the remove half of a move — the add of the
        other type is called against a scope still assigned as default."""
        config, current = self.config_and_realm()

        _, held, result = await run(kc, config, current)

        kc.remove_client_default_scope.assert_not_awaited()
        kc.add_client_optional_scope.assert_not_awaited()
        assert len(held.scope_moves) == 1
        assert result.held_back == [
            "  = svc-alpha <- alpha.write (default, a full run moves it to optional)"
        ]

    async def test_t9_a_second_additive_run_plans_no_write(self, kc):
        """T9. Idempotence. The first run adds a declared default scope and holds
        a move; the second, against what the first left, plans nothing.

        *Red:* hold back only the remove half of a move — the add is planned
        again on every run, and `has_changes` stays true.
        """
        config = KeycloakConfig(
            scopes=SCOPES,
            clients=[svc(default_scopes=["alpha.read"], optional_scopes=["alpha.write"])],
        )
        first_state = realm(client_default_scopes={"svc-alpha": {"alpha.write"}})

        first_plan, _, _ = await run(kc, config, first_state)
        assert first_plan.has_changes
        kc.add_client_default_scope.assert_awaited_once_with("uuid-alpha", "sid-read")

        # What the realm holds after the first run: the add landed, the move did not.
        second_state = realm(client_default_scopes={"svc-alpha": {"alpha.write", "alpha.read"}})
        kc.reset_mock()
        second_plan, held, _ = await run(kc, config, second_state)

        assert second_plan.has_changes is False
        assert awaited(kc, *WRITE_METHODS) == {}
        assert held.count == 1


# ---------------------------------------------------------------------------
# Mappers
# ---------------------------------------------------------------------------


class TestMappersAreKept:
    async def test_t3_a_stale_audience_mapper_on_a_declared_client_stays(self, kc):
        """T3. *Red:* filter scope assignments only — `delete_protocol_mapper` is
        awaited with the stale mapper's id."""
        config = KeycloakConfig(scopes=SCOPES, clients=[svc()])
        current = realm(client_audience_mappers={"svc-alpha": {"svc-gone": "mapper-stale"}})

        _, _, result = await run(kc, config, current)

        kc.delete_protocol_mapper.assert_not_awaited()
        assert "  = svc-alpha -> aud:svc-gone" in result.held_back

    async def test_t4_a_stale_audience_mapper_on_the_oauth2_proxy_client_stays(self, kc):
        """T4. The proxy is not in `config.clients`, and its stale mappers are
        planned in a loop of their own.

        *Red:* hold back audience removals only for clients in `config.clients`
        — the proxy's mapper is deleted.
        """
        config = KeycloakConfig(
            scopes=SCOPES,
            oauth2_proxy_client="oauth2_proxy",
            clients=[svc(scopes_prefix="alpha"), svc(client_id="tool-cli")],
        )
        current = realm(
            clients={
                "svc-alpha": {"id": "uuid-alpha", "clientId": "svc-alpha", "name": "svc-alpha"},
                "tool-cli": {"id": "uuid-cli", "clientId": "tool-cli", "name": "tool-cli"},
                "oauth2_proxy": {"id": "uuid-proxy", "clientId": "oauth2_proxy"},
            },
            client_audience_mappers={
                "oauth2_proxy": {
                    "oauth2_proxy": "m-self",
                    "svc-alpha": "m-alpha",
                    "tool-cli": "m-cli-stale",
                }
            },
        )
        unfiltered = compute_sync_plan(config, current)
        assert [a.mapper_id for a in unfiltered.audience_mappers_to_remove] == ["m-cli-stale"]

        _, _, result = await run(kc, config, current)

        kc.delete_protocol_mapper.assert_not_awaited()
        assert "  = oauth2_proxy -> aud:tool-cli" in result.held_back

    async def test_t5_a_stale_claim_mapper_stays_and_a_changed_value_still_updates(self, kc):
        """T5. *Red:* hold back the whole claim-mapper list (updates too) — the
        changed `sub` is never rewritten."""
        config = KeycloakConfig(
            scopes=SCOPES, clients=[svc(hardcoded_claims={"sub": "did:web:new"})]
        )
        current = realm(
            client_claim_mappers={
                "svc-alpha": {
                    "sub": ClaimMapperState(mapper_id="c-sub", value="did:web:old"),
                    "tenant": ClaimMapperState(mapper_id="c-tenant", value="t1"),
                }
            }
        )

        _, _, result = await run(kc, config, current)

        kc.delete_protocol_mapper.assert_not_awaited()
        kc.update_hardcoded_claim_mapper.assert_awaited_once_with(
            client_uuid="uuid-alpha",
            mapper_id="c-sub",
            claim_name="sub",
            claim_value="did:web:new",
        )
        assert "  = svc-alpha -> tenant=t1" in result.held_back


# ---------------------------------------------------------------------------
# Admin permissions
# ---------------------------------------------------------------------------


def admin_client(*grants: tuple[str, list[str]]) -> ClientConfig:
    return svc(
        admin_permissions=AdminPermissions(
            groups=[AdminGroupPermission(path=p, scopes=s) for p, s in grants]
        )
    )


def admin_realm(grants: dict[str, set[str]]) -> CurrentState:
    return realm(
        admin_permissions_enabled=True,
        admin_permissions_client_uuid="uuid-ap",
        admin_group_permissions={
            "svc-alpha": {
                path: GroupAdminGrantState(
                    permission_id=f"perm-{path.strip('/')}", scopes=set(scopes), group_id="g"
                )
                for path, scopes in grants.items()
            }
        },
    )


class TestAdminPermissionsAreKept:
    async def test_t6_a_permission_for_a_group_no_longer_named_is_not_revoked(self, kc):
        """T6. `_apply_admin_permissions` walks the plan's lists itself, apart
        from the rest of `apply_sync_plan`.

        *Red:* filter inside `apply_sync_plan`'s step loops instead of the plan
        (or drop `admin_permissions_to_remove` from the filter) — the revocation
        still lands.
        """
        config = KeycloakConfig(scopes=SCOPES, clients=[admin_client(("/kept", ["view"]))])
        current = admin_realm({"/kept": {"view"}, "/dropped": {"view", "manage-members"}})

        _, _, result = await run(kc, config, current)

        kc.delete_admin_permission.assert_not_awaited()
        assert result.admin_permissions_revoked == []
        assert "  = svc-alpha -> /dropped (manage-members, view)" in result.held_back

    async def test_q4_a_narrowed_grant_is_not_narrowed(self, kc):
        """Question 4, the safer way: a declaration dropping a scope does not
        write. *Red:* treat the narrowing as an ordinary update."""
        config = KeycloakConfig(scopes=SCOPES, clients=[admin_client(("/g", ["view"]))])
        current = admin_realm({"/g": {"view", "manage-members"}})

        _, _, result = await run(kc, config, current)

        kc.update_group_admin_permission.assert_not_awaited()
        assert "  = svc-alpha -> /g keeps manage-members" in result.held_back

    async def test_q4_a_grant_that_adds_and_drops_is_widened_only(self, kc):
        """The added scope lands; the dropped one is written back with it.
        *Red:* write the declared list as-is — `manage-members` is lost."""
        config = KeycloakConfig(
            scopes=SCOPES, clients=[admin_client(("/g", ["view", "query-members"]))]
        )
        current = admin_realm({"/g": {"view", "manage-members"}})

        await run(kc, config, current)

        kc.update_group_admin_permission.assert_awaited_once()
        written = kc.update_group_admin_permission.await_args.kwargs["scopes"]
        assert written == ["manage-members", "query-members", "view"]

    async def test_a_widening_update_applies_unchanged(self, kc):
        config = KeycloakConfig(
            scopes=SCOPES, clients=[admin_client(("/g", ["view", "query-members"]))]
        )
        current = admin_realm({"/g": {"view"}})

        _, held, _ = await run(kc, config, current)

        assert kc.update_group_admin_permission.await_args.kwargs["scopes"] == [
            "query-members",
            "view",
        ]
        assert held.count == 0


# ---------------------------------------------------------------------------
# The client rewrite (question 3)
# ---------------------------------------------------------------------------


class TestAClientUpdateKeepsLoginFlowsOn:
    """`update_client` forces the three login flows and `publicClient` off on a
    client that declares no browser login. Under `--additive` a flow the realm
    has on stays on, and is reported."""

    async def test_a_flow_on_in_the_realm_is_written_back_on(self, kc):
        """*Red:* ignore the login flags in `hold_back_removals` — the update is
        sent with `standardFlowEnabled: False`."""
        config = KeycloakConfig(scopes=SCOPES, clients=[svc(description="changed")])
        current = realm(
            clients={
                "svc-alpha": {
                    "id": "uuid-alpha",
                    "clientId": "svc-alpha",
                    "name": "svc-alpha",
                    "description": "old",
                    "serviceAccountsEnabled": True,
                    "standardFlowEnabled": True,
                    "directAccessGrantsEnabled": False,
                }
            }
        )

        _, _, result = await run(kc, config, current)

        login = kc.update_client.await_args.kwargs["login"]
        assert login["standardFlowEnabled"] is True
        assert login["implicitFlowEnabled"] is False
        assert "  = svc-alpha keeps standardFlowEnabled on" in result.held_back

    async def test_without_the_flag_the_flow_is_forced_off(self, kc):
        config = KeycloakConfig(scopes=SCOPES, clients=[svc(description="changed")])
        current = realm(
            clients={
                "svc-alpha": {
                    "id": "uuid-alpha",
                    "clientId": "svc-alpha",
                    "name": "svc-alpha",
                    "serviceAccountsEnabled": True,
                    "standardFlowEnabled": True,
                }
            }
        )

        await run(kc, config, current, additive=False)

        assert kc.update_client.await_args.kwargs["login"]["standardFlowEnabled"] is False


# ---------------------------------------------------------------------------
# What still applies, and what is reported
# ---------------------------------------------------------------------------


class TestAddsAndUpdatesStillApply:
    async def test_t7_creates_and_updates_are_written(self, kc):
        """T7. *Red:* implement `--additive` as a dry run — nothing is written."""
        config = KeycloakConfig(
            scopes=[*SCOPES, ScopeConfig(name="beta.read", description="new")],
            clients=[
                svc(
                    description="changed",
                    scopes_prefix="alpha",
                    default_scopes=["alpha.read", "beta.read"],
                ),
                svc(client_id="svc-beta", scopes_prefix="beta"),
            ],
        )
        current = realm(
            clients={
                "svc-alpha": {
                    "id": "uuid-alpha",
                    "clientId": "svc-alpha",
                    "name": "svc-alpha",
                    "description": "old",
                    "serviceAccountsEnabled": True,
                }
            },
            client_default_scopes={"svc-alpha": {"alpha.read"}},
        )
        kc.list_client_scopes.return_value = [{"name": "beta.read", "id": "scope-new"}]

        _, _, result = await run(kc, config, current)

        kc.create_client_scope.assert_awaited_once()
        kc.create_client.assert_awaited_once()
        kc.update_client.assert_awaited_once()
        kc.add_client_default_scope.assert_awaited_once_with("uuid-alpha", "scope-new")
        kc.create_audience_mapper.assert_awaited_once_with(
            client_uuid="uuid-alpha", audience_client_id="svc-beta"
        )
        assert result.success, result.errors


class TestHeldBackIsReported:
    async def test_t8_one_line_per_withheld_removal(self, kc):
        """T8. *Red:* drop the removals without recording them — the held-back
        count is 0 while the unfiltered plan held N."""
        config = KeycloakConfig(
            scopes=SCOPES,
            clients=[
                svc(optional_scopes=["alpha.write"], admin_permissions=AdminPermissions(
                    groups=[AdminGroupPermission(path="/kept", scopes=["view"])]
                ))
            ],
        )
        current = admin_realm({"/kept": {"view"}, "/dropped": {"view"}})
        current.client_default_scopes = {"svc-alpha": {"alpha.write", "hand.made"}}
        current.client_audience_mappers = {"svc-alpha": {"svc-gone": "m1"}}
        current.client_claim_mappers = {
            "svc-alpha": {"tenant": ClaimMapperState(mapper_id="c1", value="t1")}
        }

        unfiltered = compute_sync_plan(config, current)
        removals = (
            len(unfiltered.scope_assignments_to_remove)
            + len(unfiltered.audience_mappers_to_remove)
            + len(unfiltered.claim_mappers_to_remove)
            + len(unfiltered.admin_permissions_to_remove)
        )
        assert removals == 5  # hand.made, the move's remove, aud, claim, /dropped

        filtered, held = hold_back_removals(unfiltered)

        assert held.count == removals
        summary = filtered.summary()
        assert f"Held back by --additive (a full sync would remove): {removals}" in summary
        assert sum(1 for line in summary.splitlines() if line.startswith("  = ")) == removals
        assert "to remove" not in summary and "to revoke" not in summary

        await apply_sync_plan(kc, filtered, config, current)
        assert awaited(kc, *REMOVAL_METHODS) == {}

    async def test_the_input_plan_is_not_modified(self):
        config = KeycloakConfig(scopes=SCOPES, clients=[svc()])
        current = realm(client_default_scopes={"svc-alpha": {"hand.made"}})
        plan = compute_sync_plan(config, current)

        hold_back_removals(plan)

        assert len(plan.scope_assignments_to_remove) == 1

    def test_the_result_names_what_was_held(self):
        result = SyncResult(held_back=["  = svc-alpha <- hand.made (default)"])

        assert "Held back 1 removal(s)" in result.summary()
        assert "  = svc-alpha <- hand.made (default)" in result.summary()


# ---------------------------------------------------------------------------
# The realm claim-scope step (T11)
# ---------------------------------------------------------------------------


def http_client() -> KeycloakAdminClient:
    client = KeycloakAdminClient(KeycloakSettings(env="dev"))
    client.ensure_org_client_scope = AsyncMock(return_value=("org-id", False))
    client._ensure_groups_client_scope = AsyncMock(return_value=("grp-id", False))
    client._ensure_dataspace_claim_scope = AsyncMock(return_value=("ds-id", False))
    client.get_client_by_client_id = AsyncMock(return_value={"id": "proxy-uuid"})
    client._ensure_scope_default_on_client = AsyncMock(return_value=True)

    async def get(path, **_):
        if path == "/default-default-client-scopes":
            return [{"id": "org-id", "name": "organization"}, {"id": "grp-id", "name": "groups"}]
        if path == "/default-optional-client-scopes":
            return [{"id": "ds-id", "name": "dataspace"}]
        raise AssertionError(path)

    client._get = AsyncMock(side_effect=get)
    client._delete = AsyncMock()
    return client


class TestTheRealmClaimScopeStep:
    async def test_t11_additive_deletes_nothing_and_still_assigns(self):
        """T11. The claim-scope step runs before the plan exists, so filtering
        the plan cannot reach it.

        *Red:* ignore `remove_realm_defaults` — the DELETEs are issued.
        """
        client = http_client()
        kept: list[str] = []

        changed = await client.ensure_realm_claim_scopes(
            "oauth2_proxy", remove_realm_defaults=False, kept=kept
        )

        client._delete.assert_not_awaited()
        client.ensure_org_client_scope.assert_awaited_once()
        client._ensure_dataspace_claim_scope.assert_awaited_once()
        assert [c.args[1] for c in client._ensure_scope_default_on_client.await_args_list] == [
            "organization",
            "groups",
            "dataspace",
        ]
        assert kept == [
            "organization (realm default)",
            "groups (realm default)",
            "dataspace (realm optional)",
        ]
        assert changed is True  # the proxy assignment is still a change

    async def test_the_default_still_deletes(self):
        client = http_client()

        await client.ensure_realm_claim_scopes("oauth2_proxy")

        deleted = [c.args[0] for c in client._delete.await_args_list]
        assert deleted == [
            "/default-default-client-scopes/org-id",
            "/default-default-client-scopes/grp-id",
            "/default-optional-client-scopes/ds-id",
        ]

    async def test_a_dry_run_can_read_what_the_step_would_remove(self):
        client = http_client()

        assert await client.realm_claim_scopes_on_realm_lists() == [
            "organization (realm default)",
            "groups (realm default)",
            "dataspace (realm optional)",
        ]
        client._delete.assert_not_awaited()


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


class FakeKc:
    """Enough of the admin client for `_async_sync` to run end to end."""

    def __init__(self, current: CurrentState, on_lists: list[str] | None = None):
        self.current = current
        self.on_lists = on_lists or []
        self.claim_calls: list[tuple[tuple, dict]] = []
        self.authenticated = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def authenticate(self):
        self.authenticated = True

    async def ensure_realm_claim_scopes(self, *args, **kwargs):
        self.claim_calls.append((args, kwargs))
        kept = kwargs.get("kept")
        if kept is not None and kwargs.get("remove_realm_defaults") is False:
            kept.extend(self.on_lists)
        return False

    async def realm_claim_scopes_on_realm_lists(self):
        return list(self.on_lists)

    async def fetch_current_state(self):
        return self.current

    async def fetch_admin_permission_state(self, *a):
        pass


class TestTheCommand:
    async def test_additive_dry_run_reports_what_it_holds_back(self, monkeypatch, capsys):
        """The dry run never ran the claim-scope step, so it could not say what
        that step would remove. Under `--additive` it reads the realm lists.

        *Red:* skip `hold_back_removals` in the dry-run path — the removal is
        printed under "to remove" and `held_back` is empty.
        """
        import celine.policies.cli.keycloak.commands.sync as sync_command

        fake = FakeKc(
            realm(client_default_scopes={"svc-alpha": {"hand.made"}}),
            on_lists=["organization (realm default)"],
        )
        monkeypatch.setattr(sync_command, "KeycloakAdminClient", lambda *a, **k: fake)
        config = KeycloakConfig(scopes=SCOPES, clients=[svc()])

        result = await sync_command._async_sync(
            KeycloakSettings(env="dev"), config, True, False, additive=True
        )

        assert fake.claim_calls == []  # a dry run writes nothing
        assert result.held_back == [
            "  = svc-alpha <- hand.made (default)",
            "  = organization (realm default)",
        ]
        out = capsys.readouterr().out
        assert "Scope assignments to remove" not in out
        assert "Held back by --additive (a full sync would remove): 2" in out

    async def test_additive_run_passes_the_flag_to_both_claim_scope_calls(self, monkeypatch):
        """The second call, after a run that created the proxy, would otherwise
        remove what the first call kept. *Red:* pass the flag to the first call
        only."""
        import celine.policies.cli.keycloak.commands.sync as sync_command

        fake = FakeKc(CurrentState())
        monkeypatch.setattr(sync_command, "KeycloakAdminClient", lambda *a, **k: fake)

        async def apply(**kwargs):
            return SyncResult(clients_created=["oauth2_proxy"])

        monkeypatch.setattr(sync_command, "apply_sync_plan", apply)
        config = KeycloakConfig(
            oauth2_proxy_client="oauth2_proxy",
            clients=[svc(client_id="oauth2_proxy")],
        )

        await sync_command._async_sync(
            KeycloakSettings(env="dev"), config, False, False, additive=True
        )

        assert len(fake.claim_calls) == 2
        assert all(kw.get("remove_realm_defaults") is False for _, kw in fake.claim_calls)

    def test_t13_additive_and_prune_are_refused_before_authenticating(
        self, monkeypatch, tmp_path: Path
    ):
        """T13. *Red:* allow the pair — the run authenticates and goes on to
        delete orphans."""
        import celine.policies.cli.keycloak.commands.sync as sync_command

        fake = FakeKc(CurrentState())
        monkeypatch.setattr(sync_command, "KeycloakAdminClient", lambda *a, **k: fake)
        config_file = tmp_path / "clients.yaml"
        config_file.write_text("realm: celine\nscopes: []\nclients: []\n")
        monkeypatch.setenv("ENV", "dev")

        result = CliRunner().invoke(
            app, ["keycloak", "sync", str(config_file), "--additive", "--prune"]
        )

        assert result.exit_code == 2, result.output
        assert "--additive" in result.output and "--prune" in result.output
        assert fake.authenticated is False
