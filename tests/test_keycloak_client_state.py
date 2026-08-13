"""`KeycloakAdminClient`: the state it reports, and the writes it makes idempotent.

HTTP is stubbed at the method boundary, so what is under test is the logic that
sits between Keycloak's responses and the sync plan — not httpx.

Two contracts matter most:

`fetch_current_state` produces the `CurrentState` that `compute_sync_plan` diffs
against. Anything it fails to report reads as "absent", so sync plans a create
that then 409s; anything it over-reports becomes an orphan, which `--prune`
deletes. The audience-mapper filter in particular is what keeps hand-made
mappers out of the plan's removal list.

The `ensure_*` helpers are the writes that run outside the plan, on every
`sync`, `sync-users` and `sync-orgs`. They must converge and then stop: a helper
that rewrote its object each run would churn the realm forever.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from celine.policies.cli.keycloak.client import (
    AUDIENCE_MAPPER_PREFIX,
    KeycloakAdminClient,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings


@pytest.fixture
def kc() -> KeycloakAdminClient:
    """An authenticated-looking client with no live connection behind it."""
    client = KeycloakAdminClient(
        KeycloakSettings(
            base_url="http://kc.internal",
            realm="celine",
            admin_client_secret="secret",
        )
    )
    client._client = AsyncMock()
    client._token = AsyncMock()
    client._token.is_valid.return_value = True
    client._token.access_token = "fake"
    return client


def aud_mapper(audience: str, mapper_id: str = "m-1") -> dict:
    """An audience mapper as this CLI creates it."""
    return {
        "id": mapper_id,
        "name": f"{AUDIENCE_MAPPER_PREFIX}{audience}",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {
            "included.client.audience": audience,
            "id.token.claim": "false",
            "access.token.claim": "true",
        },
    }


def _stub_state(
    kc: KeycloakAdminClient,
    *,
    scopes: list[dict] | None = None,
    clients: list[dict] | None = None,
    default_scopes: list[dict] | None = None,
    optional_scopes: list[dict] | None = None,
    mappers: list[dict] | None = None,
) -> None:
    kc.list_client_scopes = AsyncMock(return_value=scopes or [])
    kc.list_clients = AsyncMock(return_value=clients or [])
    kc.get_client_default_scopes = AsyncMock(return_value=default_scopes or [])
    kc.get_client_optional_scopes = AsyncMock(return_value=optional_scopes or [])
    kc.get_client_protocol_mappers = AsyncMock(return_value=mappers or [])


# ---------------------------------------------------------------------------
# fetch_current_state
# ---------------------------------------------------------------------------


class TestFetchCurrentStateScopes:
    async def test_scopes_are_keyed_by_name(self, kc: KeycloakAdminClient):
        _stub_state(kc, scopes=[{"id": "u1", "name": "dataset.query"}])

        state = await kc.fetch_current_state()

        assert set(state.scopes) == {"dataset.query"}
        assert state.scopes["dataset.query"]["id"] == "u1"

    async def test_builtin_scopes_are_excluded(self, kc: KeycloakAdminClient):
        """They are realm defaults, so reporting them makes them orphans.

        `--prune` would then delete `profile`, `roles`, `web-origins` … and take
        OIDC login with them. `organization`, `groups` and `dataspace` are
        excluded for the same reason: they are provisioned by `ensure_*`, not by
        `clients.yaml`.
        """
        _stub_state(
            kc,
            scopes=[
                {"id": "u1", "name": "profile"},
                {"id": "u2", "name": "roles"},
                {"id": "u3", "name": "organization"},
                {"id": "u4", "name": "dataspace"},
                {"id": "u5", "name": "dataset.query"},
            ],
        )

        state = await kc.fetch_current_state()

        assert set(state.scopes) == {"dataset.query"}

    async def test_a_nameless_scope_is_skipped(self, kc: KeycloakAdminClient):
        _stub_state(kc, scopes=[{"id": "u1"}, {"id": "u2", "name": ""}])

        state = await kc.fetch_current_state()

        assert state.scopes == {}


class TestFetchCurrentStateClients:
    async def test_clients_are_keyed_by_client_id(self, kc: KeycloakAdminClient):
        _stub_state(kc, clients=[{"id": "uuid-1", "clientId": "svc-x"}])

        state = await kc.fetch_current_state()

        assert set(state.clients) == {"svc-x"}

    @pytest.mark.parametrize(
        "client_id",
        [
            "account",
            "account-console",
            "admin-cli",
            "broker",
            "realm-management",
            "security-admin-console",
        ],
    )
    async def test_keycloaks_own_clients_are_excluded(
        self, kc: KeycloakAdminClient, client_id: str
    ):
        """Every realm has these. Reporting them makes each one an orphan.

        Deleting `realm-management` would revoke the CLI's own admin roles.
        """
        _stub_state(kc, clients=[{"id": "uuid-1", "clientId": client_id}])

        state = await kc.fetch_current_state()

        assert state.clients == {}

    async def test_scope_assignments_are_recorded_as_name_sets(
        self, kc: KeycloakAdminClient
    ):
        _stub_state(
            kc,
            clients=[{"id": "uuid-1", "clientId": "svc-x"}],
            default_scopes=[{"name": "dataset.query"}, {"name": "profile"}],
            optional_scopes=[{"name": "dataset.admin"}],
        )

        state = await kc.fetch_current_state()

        assert state.client_default_scopes["svc-x"] == {"dataset.query", "profile"}
        assert state.client_optional_scopes["svc-x"] == {"dataset.admin"}

    async def test_a_nameless_assignment_is_dropped(self, kc: KeycloakAdminClient):
        _stub_state(
            kc,
            clients=[{"id": "uuid-1", "clientId": "svc-x"}],
            default_scopes=[{"name": "dataset.query"}, {"id": "no-name"}],
        )

        state = await kc.fetch_current_state()

        assert state.client_default_scopes["svc-x"] == {"dataset.query"}


class TestFetchCurrentStateAudienceMappers:
    """Only this CLI's own mappers may appear — the plan removes what it sees."""

    async def test_a_managed_mapper_is_reported_by_audience(
        self, kc: KeycloakAdminClient
    ):
        _stub_state(
            kc,
            clients=[{"id": "uuid-1", "clientId": "svc-x"}],
            mappers=[aud_mapper("svc-dataset-api", "m-1")],
        )

        state = await kc.fetch_current_state()

        assert state.client_audience_mappers["svc-x"] == {"svc-dataset-api": "m-1"}

    async def test_a_hand_made_mapper_is_ignored(self, kc: KeycloakAdminClient):
        """Same type, different name — somebody added it on purpose.

        Without the name filter, the next `sync` would delete it.
        """
        mapper = aud_mapper("grafana", "m-ext")
        mapper["name"] = "my-custom-audience"
        _stub_state(kc, clients=[{"id": "uuid-1", "clientId": "svc-x"}], mappers=[mapper])

        state = await kc.fetch_current_state()

        assert state.client_audience_mappers["svc-x"] == {}

    async def test_mappers_of_other_types_are_ignored(self, kc: KeycloakAdminClient):
        """A name collision must not make a group mapper look like an audience."""
        _stub_state(
            kc,
            clients=[{"id": "uuid-1", "clientId": "svc-x"}],
            mappers=[
                {
                    "id": "m-2",
                    "name": f"{AUDIENCE_MAPPER_PREFIX}looks-like-one",
                    "protocolMapper": "oidc-group-membership-mapper",
                    "config": {"included.client.audience": "nope"},
                }
            ],
        )

        state = await kc.fetch_current_state()

        assert state.client_audience_mappers["svc-x"] == {}

    async def test_a_mapper_without_an_audience_config_is_ignored(
        self, kc: KeycloakAdminClient
    ):
        """Otherwise the dict comprehension would key on a missing value."""
        broken = aud_mapper("svc-y", "m-3")
        broken["config"] = {}
        _stub_state(kc, clients=[{"id": "uuid-1", "clientId": "svc-x"}], mappers=[broken])

        state = await kc.fetch_current_state()

        assert state.client_audience_mappers["svc-x"] == {}

    async def test_the_reported_audience_is_the_config_not_the_name(
        self, kc: KeycloakAdminClient
    ):
        """The name is cosmetic; `included.client.audience` is what lands in `aud`.

        If they disagree, the config is the truth — planning against the name
        would leave a token asserting an audience nobody expects.
        """
        mapper = aud_mapper("real-audience", "m-4")
        mapper["name"] = f"{AUDIENCE_MAPPER_PREFIX}stale-name"
        _stub_state(kc, clients=[{"id": "uuid-1", "clientId": "svc-x"}], mappers=[mapper])

        state = await kc.fetch_current_state()

        assert state.client_audience_mappers["svc-x"] == {"real-audience": "m-4"}


# ---------------------------------------------------------------------------
# Audience mapper writes
# ---------------------------------------------------------------------------


class TestAudienceMapperCreation:
    async def test_the_payload_puts_the_audience_in_the_access_token(
        self, kc: KeycloakAdminClient
    ):
        """`aud` is validated on access tokens; an id-token-only mapper is useless."""
        kc._post = AsyncMock(return_value={"id": "m-new"})

        mapper_id = await kc.create_audience_mapper("uuid-1", "svc-dataset-api")

        assert mapper_id == "m-new"
        payload = kc._post.call_args.kwargs["json"]
        assert payload["protocolMapper"] == "oidc-audience-mapper"
        assert payload["config"]["included.client.audience"] == "svc-dataset-api"
        assert payload["config"]["access.token.claim"] == "true"

    async def test_the_mapper_name_carries_the_managed_prefix(
        self, kc: KeycloakAdminClient
    ):
        """This name is the sentinel `fetch_current_state` filters on.

        Drift here and the tool stops recognising its own mappers: it would
        re-add one on every run and never clean an obsolete one up.
        """
        kc._post = AsyncMock(return_value={"id": "m-new"})

        await kc.create_audience_mapper("uuid-1", "svc-dataset-api")

        assert (
            kc._post.call_args.kwargs["json"]["name"]
            == f"{AUDIENCE_MAPPER_PREFIX}svc-dataset-api"
        )

    async def test_the_id_is_looked_up_when_the_post_returns_nothing(
        self, kc: KeycloakAdminClient
    ):
        """Keycloak answers 201 with an empty body; the plan still needs the id."""
        kc._post = AsyncMock(return_value=None)
        kc.get_client_protocol_mappers = AsyncMock(
            return_value=[aud_mapper("svc-dataset-api", "m-found")]
        )

        assert await kc.create_audience_mapper("uuid-1", "svc-dataset-api") == "m-found"

    async def test_ensure_is_a_no_op_when_the_mapper_exists(
        self, kc: KeycloakAdminClient
    ):
        kc.get_client_protocol_mappers = AsyncMock(
            return_value=[aud_mapper("svc-dataset-api")]
        )
        kc.create_audience_mapper = AsyncMock()

        created = await kc.ensure_audience_mapper("uuid-1", "svc-dataset-api")

        assert created is False
        kc.create_audience_mapper.assert_not_awaited()

    async def test_ensure_creates_the_mapper_when_absent(self, kc: KeycloakAdminClient):
        kc.get_client_protocol_mappers = AsyncMock(return_value=[])
        kc.create_audience_mapper = AsyncMock(return_value="m-new")

        created = await kc.ensure_audience_mapper("uuid-1", "svc-dataset-api")

        assert created is True
        kc.create_audience_mapper.assert_awaited_once_with("uuid-1", "svc-dataset-api")

    async def test_a_mapper_for_another_audience_does_not_satisfy_it(
        self, kc: KeycloakAdminClient
    ):
        kc.get_client_protocol_mappers = AsyncMock(
            return_value=[aud_mapper("svc-nudging")]
        )
        kc.create_audience_mapper = AsyncMock(return_value="m-new")

        assert await kc.ensure_audience_mapper("uuid-1", "svc-dataset-api") is True


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------


class TestEnsureOrganization:
    """`sync-orgs` and `sync-users` both call this on every run."""

    async def test_an_absent_organization_is_created(self, kc: KeycloakAdminClient):
        kc.get_organization_by_alias = AsyncMock(return_value=None)
        kc.create_organization = AsyncMock(return_value="org-1")

        org_id, created = await kc.ensure_organization(
            alias="greenland", name="Greenland", attributes={"type": ["rec"]}
        )

        assert (org_id, created) == ("org-1", True)
        kc.create_organization.assert_awaited_once_with(
            "greenland", "Greenland", "", {"type": ["rec"]}
        )

    async def test_an_existing_organization_is_not_recreated(
        self, kc: KeycloakAdminClient
    ):
        kc.get_organization_by_alias = AsyncMock(
            return_value={"id": "org-1", "alias": "greenland", "attributes": {"type": ["rec"]}}
        )
        kc.create_organization = AsyncMock()
        kc._put = AsyncMock()

        org_id, created = await kc.ensure_organization(
            alias="greenland", name="Greenland", attributes={"type": ["rec"]}
        )

        assert (org_id, created) == ("org-1", False)
        kc.create_organization.assert_not_awaited()
        kc._put.assert_not_awaited()

    async def test_drifted_attributes_are_upserted(self, kc: KeycloakAdminClient):
        """The `type` attribute is what tells a REC org from a DSO one.

        A stale value there mislabels the organization for anything reading the
        claim, so an existing org is corrected rather than left alone.
        """
        kc.get_organization_by_alias = AsyncMock(
            return_value={"id": "org-1", "alias": "greenland", "attributes": {"type": ["dso"]}}
        )
        kc._put = AsyncMock()

        _, created = await kc.ensure_organization(
            alias="greenland", name="Greenland", attributes={"type": ["rec"]}
        )

        assert created is False
        kc._put.assert_awaited_once()
        assert kc._put.call_args.kwargs["json"]["attributes"] == {"type": ["rec"]}

    async def test_no_attributes_means_no_write_at_all(self, kc: KeycloakAdminClient):
        kc.get_organization_by_alias = AsyncMock(
            return_value={"id": "org-1", "attributes": {"type": ["rec"]}}
        )
        kc._put = AsyncMock()

        await kc.ensure_organization(alias="greenland", name="Greenland")

        kc._put.assert_not_awaited()

    async def test_lookup_matches_on_alias_not_name(self, kc: KeycloakAdminClient):
        """Keycloak's org search matches names, which are not unique.

        Two organizations can share a display name; the alias is the identity
        `sync-orgs` provisions against.
        """
        kc.list_organizations = AsyncMock(
            return_value=[
                {"id": "org-other", "alias": "other", "name": "Greenland"},
                {"id": "org-1", "alias": "greenland", "name": "Something Else"},
            ]
        )

        org = await kc.get_organization_by_alias("greenland")

        assert org["id"] == "org-1"

    async def test_an_unknown_alias_yields_none(self, kc: KeycloakAdminClient):
        kc.list_organizations = AsyncMock(return_value=[{"id": "o", "alias": "other"}])

        assert await kc.get_organization_by_alias("greenland") is None


# ---------------------------------------------------------------------------
# Roles the CLI needs to do any of this
# ---------------------------------------------------------------------------


class TestRequiredRealmRoles:
    def test_the_required_roles_cover_every_command(self):
        """`bootstrap` grants exactly this list to `celine-admin-cli`.

        A command needing a role that is missing here fails mid-run, after the
        earlier writes have already landed.
        """
        required = set(KeycloakAdminClient.REQUIRED_REALM_MGMT_ROLES)

        # keycloak sync — clients, scopes, protocol mappers
        assert {"manage-clients", "view-clients"} <= required
        # sync-users / set-password / set-user-organization
        assert {"manage-users", "view-users"} <= required
        # organizations and groups live on the realm
        assert {"manage-realm", "view-realm"} <= required
        assert {"query-groups", "query-users"} <= required
