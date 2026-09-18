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
    CLAIM_MAPPER_PREFIX,
    ClaimMapperState,
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


def claim_mapper(name: str, value: str, mapper_id: str = "c-1") -> dict:
    """A hardcoded claim mapper as this CLI creates it."""
    return {
        "id": mapper_id,
        "name": f"{CLAIM_MAPPER_PREFIX}{name}",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {
            "claim.name": name,
            "claim.value": value,
            "jsonType.label": "String",
            "access.token.claim": "true",
            "id.token.claim": "false",
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
# Hardcoded claim mappers
# ---------------------------------------------------------------------------


class TestFetchCurrentStateClaimMappers:
    """The `claim-` sentinel, and the value the plan diffs against."""

    async def test_a_managed_mapper_is_reported_with_its_value(
        self, kc: KeycloakAdminClient
    ):
        _stub_state(
            kc,
            clients=[{"id": "uuid-1", "clientId": "svc-x"}],
            mappers=[claim_mapper("sub", "did:web:x", "c-1")],
        )

        state = await kc.fetch_current_state()

        assert state.client_claim_mappers["svc-x"] == {
            "sub": ClaimMapperState(mapper_id="c-1", value="did:web:x")
        }

    async def test_a_hand_made_mapper_is_ignored(self, kc: KeycloakAdminClient):
        """Same type, different name — somebody pinned that claim on purpose."""
        mapper = claim_mapper("sub", "did:web:theirs")
        mapper["name"] = "their-own-sub"
        _stub_state(
            kc, clients=[{"id": "uuid-1", "clientId": "svc-x"}], mappers=[mapper]
        )

        state = await kc.fetch_current_state()

        assert state.client_claim_mappers["svc-x"] == {}

    async def test_mappers_of_other_types_are_ignored(self, kc: KeycloakAdminClient):
        """A `claim-` name on another mapper type is not this tool's to remove."""
        _stub_state(
            kc,
            clients=[{"id": "uuid-1", "clientId": "svc-x"}],
            mappers=[
                {
                    "id": "c-2",
                    "name": f"{CLAIM_MAPPER_PREFIX}looks-like-one",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {"claim.name": "sub"},
                }
            ],
        )

        state = await kc.fetch_current_state()

        assert state.client_claim_mappers["svc-x"] == {}

    async def test_an_audience_mapper_is_not_read_as_a_claim(
        self, kc: KeycloakAdminClient
    ):
        """The two families share a client and must not see each other's mappers."""
        _stub_state(
            kc,
            clients=[{"id": "uuid-1", "clientId": "svc-x"}],
            mappers=[aud_mapper("svc-dataset-api", "m-1")],
        )

        state = await kc.fetch_current_state()

        assert state.client_claim_mappers["svc-x"] == {}
        assert state.client_audience_mappers["svc-x"] == {"svc-dataset-api": "m-1"}

    async def test_a_mapper_without_a_claim_name_is_ignored(
        self, kc: KeycloakAdminClient
    ):
        """Otherwise the dict comprehension would key on a missing value."""
        broken = claim_mapper("sub", "did:web:x")
        broken["config"] = {}
        _stub_state(
            kc, clients=[{"id": "uuid-1", "clientId": "svc-x"}], mappers=[broken]
        )

        state = await kc.fetch_current_state()

        assert state.client_claim_mappers["svc-x"] == {}

    async def test_the_reported_claim_is_the_config_not_the_name(
        self, kc: KeycloakAdminClient
    ):
        """`claim.name` is what lands in the token; the mapper name is cosmetic."""
        mapper = claim_mapper("sub", "did:web:x", "c-4")
        mapper["name"] = f"{CLAIM_MAPPER_PREFIX}stale-name"
        _stub_state(
            kc, clients=[{"id": "uuid-1", "clientId": "svc-x"}], mappers=[mapper]
        )

        state = await kc.fetch_current_state()

        assert set(state.client_claim_mappers["svc-x"]) == {"sub"}


class TestClaimMapperWrites:
    async def test_the_payload_overrides_the_claim_in_the_access_token(
        self, kc: KeycloakAdminClient
    ):
        """EDC reads `sub` off the access token, and off introspection."""
        kc._post = AsyncMock(return_value={"id": "c-new"})

        mapper_id = await kc.create_hardcoded_claim_mapper(
            "uuid-1", "sub", "did:web:example-rec"
        )

        assert mapper_id == "c-new"
        payload = kc._post.call_args.kwargs["json"]
        assert payload["protocolMapper"] == "oidc-hardcoded-claim-mapper"
        assert payload["protocol"] == "openid-connect"
        assert payload["config"] == {
            "claim.name": "sub",
            "claim.value": "did:web:example-rec",
            "jsonType.label": "String",
            "access.token.claim": "true",
            "id.token.claim": "false",
            "userinfo.token.claim": "false",
            "introspection.token.claim": "true",
            "access.tokenResponse.claim": "false",
        }

    async def test_the_mapper_name_carries_the_managed_prefix(
        self, kc: KeycloakAdminClient
    ):
        """This name is the sentinel `fetch_current_state` filters on."""
        kc._post = AsyncMock(return_value={"id": "c-new"})

        await kc.create_hardcoded_claim_mapper("uuid-1", "sub", "did:web:x")

        assert kc._post.call_args.kwargs["json"]["name"] == f"{CLAIM_MAPPER_PREFIX}sub"

    async def test_the_id_is_looked_up_when_the_post_returns_nothing(
        self, kc: KeycloakAdminClient
    ):
        """Keycloak answers 201 with an empty body; the plan still needs the id."""
        kc._post = AsyncMock(return_value=None)
        kc.get_client_protocol_mappers = AsyncMock(
            return_value=[claim_mapper("sub", "did:web:x", "c-found")]
        )

        created = await kc.create_hardcoded_claim_mapper("uuid-1", "sub", "did:web:x")

        assert created == "c-found"

    async def test_an_update_puts_the_whole_representation_with_its_id(
        self, kc: KeycloakAdminClient
    ):
        """A PUT that omits a config key is a PUT that drops it."""
        kc._put = AsyncMock(return_value=None)

        await kc.update_hardcoded_claim_mapper("uuid-1", "c-1", "sub", "did:web:new")

        path = kc._put.call_args.args[0]
        payload = kc._put.call_args.kwargs["json"]
        assert path == "/clients/uuid-1/protocol-mappers/models/c-1"
        assert payload["id"] == "c-1"
        assert payload["config"]["claim.value"] == "did:web:new"
        assert payload["config"]["jsonType.label"] == "String"

    async def test_ensure_is_a_no_op_when_the_value_already_matches(
        self, kc: KeycloakAdminClient
    ):
        kc.get_client_protocol_mappers = AsyncMock(
            return_value=[claim_mapper("sub", "did:web:x")]
        )
        kc.create_hardcoded_claim_mapper = AsyncMock()
        kc.update_hardcoded_claim_mapper = AsyncMock()

        written = await kc.ensure_hardcoded_claim_mapper("uuid-1", "sub", "did:web:x")

        assert written is False
        kc.create_hardcoded_claim_mapper.assert_not_awaited()
        kc.update_hardcoded_claim_mapper.assert_not_awaited()

    async def test_ensure_creates_the_mapper_when_absent(self, kc: KeycloakAdminClient):
        kc.get_client_protocol_mappers = AsyncMock(return_value=[])
        kc.create_hardcoded_claim_mapper = AsyncMock(return_value="c-new")

        written = await kc.ensure_hardcoded_claim_mapper("uuid-1", "sub", "did:web:x")

        assert written is True
        kc.create_hardcoded_claim_mapper.assert_awaited_once_with(
            "uuid-1", "sub", "did:web:x"
        )

    async def test_ensure_rewrites_a_different_value_in_place(
        self, kc: KeycloakAdminClient
    ):
        """Never a delete and a create: the gap emits Keycloak's own `sub`."""
        kc.get_client_protocol_mappers = AsyncMock(
            return_value=[claim_mapper("sub", "did:web:old", "c-1")]
        )
        kc.create_hardcoded_claim_mapper = AsyncMock()
        kc.update_hardcoded_claim_mapper = AsyncMock()

        written = await kc.ensure_hardcoded_claim_mapper("uuid-1", "sub", "did:web:new")

        assert written is True
        kc.create_hardcoded_claim_mapper.assert_not_awaited()
        kc.update_hardcoded_claim_mapper.assert_awaited_once_with(
            "uuid-1", "c-1", "sub", "did:web:new"
        )


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------


class TestEnsureOrganization:
    """`sync-orgs` and `sync-users` both call this on every run."""

    async def test_an_absent_organization_is_created(self, kc: KeycloakAdminClient):
        kc.get_organization_by_alias = AsyncMock(return_value=None)
        kc.create_organization = AsyncMock(return_value="org-1")

        org_id, created = await kc.ensure_organization(
            alias="example-rec", name="Example REC", attributes={"type": ["rec"]}
        )

        assert (org_id, created) == ("org-1", True)
        kc.create_organization.assert_awaited_once_with(
            "example-rec", "Example REC", "", {"type": ["rec"]}
        )

    async def test_an_existing_organization_is_not_recreated(
        self, kc: KeycloakAdminClient
    ):
        kc.get_organization_by_alias = AsyncMock(
            return_value={"id": "org-1", "alias": "example-rec", "attributes": {"type": ["rec"]}}
        )
        kc.create_organization = AsyncMock()
        kc._put = AsyncMock()

        org_id, created = await kc.ensure_organization(
            alias="example-rec", name="Example REC", attributes={"type": ["rec"]}
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
            return_value={"id": "org-1", "alias": "example-rec", "attributes": {"type": ["dso"]}}
        )
        kc._put = AsyncMock()

        _, created = await kc.ensure_organization(
            alias="example-rec", name="Example REC", attributes={"type": ["rec"]}
        )

        assert created is False
        kc._put.assert_awaited_once()
        assert kc._put.call_args.kwargs["json"]["attributes"] == {"type": ["rec"]}

    async def test_no_attributes_means_no_write_at_all(self, kc: KeycloakAdminClient):
        kc.get_organization_by_alias = AsyncMock(
            return_value={"id": "org-1", "attributes": {"type": ["rec"]}}
        )
        kc._put = AsyncMock()

        await kc.ensure_organization(alias="example-rec", name="Example REC")

        kc._put.assert_not_awaited()

    async def test_lookup_matches_on_alias_not_name(self, kc: KeycloakAdminClient):
        """Keycloak's org search matches names, which are not unique.

        Two organizations can share a display name; the alias is the identity
        `sync-orgs` provisions against.
        """
        kc.list_organizations = AsyncMock(
            return_value=[
                {"id": "org-other", "alias": "other", "name": "Example REC"},
                {"id": "org-1", "alias": "example-rec", "name": "Something Else"},
            ]
        )

        org = await kc.get_organization_by_alias("example-rec")

        assert org["id"] == "org-1"

    async def test_an_unknown_alias_yields_none(self, kc: KeycloakAdminClient):
        kc.list_organizations = AsyncMock(return_value=[{"id": "o", "alias": "other"}])

        assert await kc.get_organization_by_alias("example-rec") is None


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


class TestReadingOneUsersMembership:
    """Two reads `--check` rests on, and both are "ask about one, not list all".

    The listing alternatives are the trap. `GET /organizations/{id}/members`
    takes no `first`/`max`, so a large organization answers with whatever page
    Keycloak chooses and a member past the end reads as absent. And
    `GET /groups/{id}/members` ignores `search` and `exact` (ADR-0004), so
    finding one participant in a flat group holding every participant on the
    deployment is a paged scan.

    Either one under-reports, and a check that manufactures findings is worse
    than no check: an operator who chases one false positive stops reading the
    next real finding.
    """

    @pytest.mark.asyncio
    async def test_a_member_answers_true(self, kc: KeycloakAdminClient):
        kc._get = AsyncMock(return_value={"id": "uuid-1"})

        assert await kc.is_user_in_organization("org-1", "uuid-1") is True
        kc._get.assert_awaited_once_with("/organizations/org-1/members/uuid-1")

    @pytest.mark.asyncio
    async def test_a_non_member_answers_false_rather_than_raising(
        self, kc: KeycloakAdminClient
    ):
        """Keycloak says 404 for "not a member", which is not an error here."""
        from celine.policies.cli.keycloak.client import KeycloakNotFoundError

        kc._get = AsyncMock(side_effect=KeycloakNotFoundError("nope"))

        assert await kc.is_user_in_organization("org-1", "uuid-1") is False

    @pytest.mark.asyncio
    async def test_ensure_user_in_organization_uses_the_same_check(
        self, kc: KeycloakAdminClient
    ):
        """One membership test, so the check and the write cannot disagree.

        A `--check` that reported a member absent while the sync considered them
        present — or the reverse — would make the two commands argue about the
        same realm.
        """
        kc.is_user_in_organization = AsyncMock(return_value=True)
        kc.add_user_to_organization = AsyncMock()

        assert await kc.ensure_user_in_organization("org-1", "uuid-1") is False
        kc.add_user_to_organization.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_users_groups_come_back_as_paths(self, kc: KeycloakAdminClient):
        kc._get = AsyncMock(
            return_value=[
                {"id": "g-1", "name": "participants", "path": "/participants"},
                {"id": "g-2", "name": "viewers", "path": "/viewers"},
            ]
        )

        groups = await kc.get_user_groups("uuid-1")

        assert [g["path"] for g in groups] == ["/participants", "/viewers"]
        kc._get.assert_awaited_once_with("/users/uuid-1/groups")

    @pytest.mark.asyncio
    async def test_a_user_in_no_group_is_an_empty_list_not_none(
        self, kc: KeycloakAdminClient
    ):
        """`_get` returns None on an empty body, and the caller iterates."""
        kc._get = AsyncMock(return_value=None)

        assert await kc.get_user_groups("uuid-1") == []
