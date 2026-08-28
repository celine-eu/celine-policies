"""Tests for the dataspace client scope and new dataspace service clients."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from celine.policies.cli.keycloak.client import KeycloakAdminClient
from celine.policies.cli.keycloak.models import KeycloakConfig
from celine.policies.cli.keycloak.settings import KeycloakSettings


def _make_settings() -> KeycloakSettings:
    return KeycloakSettings(
        base_url="http://localhost:8080",
        realm="celine",
        admin_user="admin",
        admin_password="admin",
    )


# ---------------------------------------------------------------------------
# P1 — _ensure_dataspace_claim_scope
# ---------------------------------------------------------------------------


class TestEnsureDataspaceClaimScope:
    """Tests for _ensure_dataspace_claim_scope()."""

    async def test_creates_scope_and_mapper_when_absent(self):
        client = KeycloakAdminClient(_make_settings())
        client._client = AsyncMock()
        client._token = AsyncMock()
        client._token.is_valid.return_value = True
        client._token.access_token = "fake"

        client.get_client_scope_by_name = AsyncMock(return_value=None)
        client.create_client_scope = AsyncMock(return_value="scope-uuid-1")
        client.get_scope_protocol_mappers = AsyncMock(return_value=[])
        client._post = AsyncMock(return_value=None)

        scope_id, changed = await client._ensure_dataspace_claim_scope()

        assert scope_id == "scope-uuid-1"
        assert changed is True
        client.create_client_scope.assert_awaited_once_with(
            name="dataspace", description="Dataspace DID claims"
        )
        client._post.assert_awaited_once()
        call_args = client._post.call_args
        mapper_payload = call_args.kwargs.get("json") or call_args[1].get("json")
        assert mapper_payload["name"] == "dataspace-did"
        assert mapper_payload["protocolMapper"] == "oidc-usermodel-attribute-mapper"
        assert mapper_payload["config"]["claim.name"] == "dataspace_did"
        assert mapper_payload["config"]["user.attribute"] == "dataspace_did"

    async def test_idempotent_when_scope_and_mapper_exist(self):
        client = KeycloakAdminClient(_make_settings())
        client._client = AsyncMock()
        client._token = AsyncMock()
        client._token.is_valid.return_value = True
        client._token.access_token = "fake"

        client.get_client_scope_by_name = AsyncMock(
            return_value={"id": "scope-uuid-1", "name": "dataspace"}
        )
        client.get_scope_protocol_mappers = AsyncMock(
            return_value=[
                {
                    "name": "dataspace-did",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "claim.name": "dataspace_did",
                        "user.attribute": "dataspace_did",
                        "jsonType.label": "String",
                        "id.token.claim": "true",
                        "access.token.claim": "true",
                        "userinfo.token.claim": "true",
                    },
                }
            ]
        )

        scope_id, changed = await client._ensure_dataspace_claim_scope()

        assert scope_id == "scope-uuid-1"
        assert changed is False

    async def test_updates_mapper_on_config_drift(self):
        client = KeycloakAdminClient(_make_settings())
        client._client = AsyncMock()
        client._token = AsyncMock()
        client._token.is_valid.return_value = True
        client._token.access_token = "fake"

        client.get_client_scope_by_name = AsyncMock(
            return_value={"id": "scope-uuid-1", "name": "dataspace"}
        )
        client.get_scope_protocol_mappers = AsyncMock(
            return_value=[
                {
                    "id": "mapper-uuid-1",
                    "name": "dataspace-did",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "claim.name": "dataspace_did",
                        "user.attribute": "dataspace_did",
                        "jsonType.label": "String",
                        "id.token.claim": "false",  # drifted
                        "access.token.claim": "true",
                        "userinfo.token.claim": "true",
                    },
                }
            ]
        )
        client.update_scope_protocol_mapper = AsyncMock()

        scope_id, changed = await client._ensure_dataspace_claim_scope()

        assert scope_id == "scope-uuid-1"
        assert changed is True
        client.update_scope_protocol_mapper.assert_awaited_once()


# ---------------------------------------------------------------------------
# ensure_realm_claim_scopes calls _ensure_dataspace_claim_scope
# ---------------------------------------------------------------------------


class TestRealmClaimScopesIncludesDataspace:
    async def test_calls_all_three_scope_functions(self):
        client = KeycloakAdminClient(_make_settings())
        client._client = AsyncMock()
        client._token = AsyncMock()
        client._token.is_valid.return_value = True
        client._token.access_token = "fake"

        client.ensure_org_client_scope = AsyncMock(return_value=("org-id", False))
        client._ensure_groups_client_scope = AsyncMock(return_value=("grp-id", False))
        client._ensure_dataspace_claim_scope = AsyncMock(return_value=("ds-id", False))
        client._ensure_scope_not_realm_default = AsyncMock(return_value=False)

        changed = await client.ensure_realm_claim_scopes()

        assert changed is False
        client.ensure_org_client_scope.assert_awaited_once()
        client._ensure_groups_client_scope.assert_awaited_once()
        client._ensure_dataspace_claim_scope.assert_awaited_once()
        assert client._ensure_scope_not_realm_default.await_count == 3

    async def test_assigns_dataspace_as_default_on_oauth2_proxy(self):
        client = KeycloakAdminClient(_make_settings())
        client._client = AsyncMock()
        client._token = AsyncMock()
        client._token.is_valid.return_value = True
        client._token.access_token = "fake"

        client.ensure_org_client_scope = AsyncMock(return_value=("org-id", False))
        client._ensure_groups_client_scope = AsyncMock(return_value=("grp-id", False))
        client._ensure_dataspace_claim_scope = AsyncMock(return_value=("ds-id", False))
        client._ensure_scope_not_realm_default = AsyncMock(return_value=False)
        client.get_client_by_client_id = AsyncMock(
            return_value={"id": "proxy-uuid"}
        )
        client._ensure_scope_default_on_client = AsyncMock(return_value=False)

        await client.ensure_realm_claim_scopes("oauth2_proxy")

        scope_names_assigned = [
            call.args[1]
            for call in client._ensure_scope_default_on_client.call_args_list
        ]
        assert "organization" in scope_names_assigned
        assert "groups" in scope_names_assigned
        assert "dataspace" in scope_names_assigned


# ---------------------------------------------------------------------------
# BUILTIN_SCOPES includes 'dataspace'
# ---------------------------------------------------------------------------


def test_dataspace_in_builtin_scopes():
    assert "dataspace" in KeycloakAdminClient.BUILTIN_SCOPES


# ---------------------------------------------------------------------------
# P2+P3 — clients.yaml parsing
# ---------------------------------------------------------------------------


CLIENTS_YAML = Path(__file__).resolve().parents[1] / "clients.yaml"
DS_HOST_YAML = Path(__file__).resolve().parents[1] / "clients.ds-host.yaml"


class TestClientsYamlDataspaceEntries:
    def test_parses_without_error(self):
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)
        assert len(config.clients) > 0
        assert len(config.scopes) > 0

    # ------------------------------------------------------------------
    # The dataspace clients are declared by ds, not here. What follows
    # asserts the grants *celine* adds to them, which live in
    # clients.ds-host.yaml and are the only part of those clients this
    # repository decides. Their identity — name, secret, scopes_prefix,
    # service_account_enabled — is ds's and is deliberately not pinned here
    # any more: pinning it is what let the old hand-pasted copy drift.
    # ------------------------------------------------------------------

    def test_identity_registry_admin_scope_defined(self):
        """celine grants the superset, so celine declares it.

        ds drops every `*.admin` from what it carries into a host realm, so a
        realm that grants one has to declare it itself.
        """
        host = KeycloakConfig.from_yaml(DS_HOST_YAML)
        assert "identity-registry.admin" in host.get_scope_names()

    def test_ds_identity_registry_client(self):
        host = KeycloakConfig.from_yaml(DS_HOST_YAML)
        ir = next(c for c in host.clients if c.client_id == "svc-ds-identity-registry")
        assert "identity-registry.admin" in ir.default_scopes

    def test_ds_onboarding_client(self):
        """The one grant ds cannot carry: rec-registry is celine's service."""
        host = KeycloakConfig.from_yaml(DS_HOST_YAML)
        ob = next(c for c in host.clients if c.client_id == "svc-ds-onboarding")
        assert "rec-registry.members.write" in ob.default_scopes
        assert "svc-rec-registry" in ob.extra_audiences

    def test_ds_onboarding_holds_no_registry_admin_scope(self):
        """The least-privilege realignment must not be undone.

        This client used to hold `identity-registry.admin`, which also covers
        creating and deleting organizations — authority an onboarding flow has
        no use for. Re-adding it would silently widen the blast radius of a
        compromised onboarding service back to the whole identity registry.
        ds grants it the enumerated writes instead; celine must not add the
        superset back on top.
        """
        host = KeycloakConfig.from_yaml(DS_HOST_YAML)
        ob = next(c for c in host.clients if c.client_id == "svc-ds-onboarding")
        assert "identity-registry.admin" not in ob.default_scopes
        assert "identity-registry.admin" not in ob.optional_scopes

    def test_ds_onboarding_is_granted_nothing_ds_already_grants(self):
        """A host-side grant that repeats ds's is how the last copy started.

        The union is the same either way, so a duplicate is invisible until it
        drifts. Kept narrow: only the scopes ds's own file lists for this
        client, which are the ones this repository used to duplicate.
        """
        host = KeycloakConfig.from_yaml(DS_HOST_YAML)
        ob = next(c for c in host.clients if c.client_id == "svc-ds-onboarding")
        ds_owned = {
            "identity-registry.organizations.read",
            "identity-registry.credentials.write",
            "identity-registry.memberships.write",
            "identity-registry.keycloak.sync",
            "identity-registry.resolve",
            "connector.consent.provision",
            "connector.consent.audience",
            "connector.disclosure.record",
            "provenance.write",
        }
        assert not ds_owned & set(ob.default_scopes), (
            "clients.ds-host.yaml repeats a grant ds's own file already makes"
        )

    def test_ds_portal_client(self):
        """The portal calls celine's dataset-api as itself."""
        host = KeycloakConfig.from_yaml(DS_HOST_YAML)
        portal = next(c for c in host.clients if c.client_id == "svc-ds-portal")
        assert "dataset.query" in portal.default_scopes
        assert "dataset.read" in portal.default_scopes
        assert "svc-dataset-api" in portal.extra_audiences

    def test_ds_portal_reaches_the_registry_read_only(self):
        """A browser-facing portal must not be able to mint or revoke identity.

        It resolves and reads; issuing credentials belongs to the onboarding
        service, which is not exposed to end users. This asserts what celine
        adds — ds's own grants to the portal are ds's to justify.
        """
        host = KeycloakConfig.from_yaml(DS_HOST_YAML)
        portal = next(c for c in host.clients if c.client_id == "svc-ds-portal")
        registry_scopes = [
            s for s in portal.default_scopes if s.startswith("identity-registry.")
        ]
        assert registry_scopes, "portal no longer talks to the identity registry?"
        assert all(s.endswith(".read") or s.endswith(".resolve") for s in registry_scopes)
        assert "identity-registry.admin" not in portal.default_scopes

    def test_the_host_overlay_declares_no_dataspace_client(self):
        """Every entry is grants-only, or celine is claiming a client ds owns.

        A second file declaring identity is a merge error naming both files —
        this fails first, and says why.
        """
        import yaml

        raw = yaml.safe_load(DS_HOST_YAML.read_text())
        identity = {
            "name",
            "description",
            "secret",
            "scopes_prefix",
            "service_account_enabled",
        }
        grants = {"client_id", "default_scopes", "optional_scopes", "extra_audiences"}
        for entry in raw["clients"]:
            claimed = set(entry) & identity
            assert not claimed, (
                f"{entry['client_id']} declares {sorted(claimed)} — ds owns this "
                "client's identity, and a second file declaring it is a merge error"
            )
            assert set(entry) <= grants, (
                f"{entry['client_id']} carries {sorted(set(entry) - grants)}, which "
                "makes the entry an ownership claim rather than a grant"
            )

    def test_no_undefined_scope_references(self):
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)
        undefined = config.validate_scope_references()
        assert undefined == [], f"Undefined scopes referenced: {undefined}"

    def test_backward_compat_existing_clients_unchanged(self):
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)
        client_ids = config.get_client_ids()
        for expected in [
            "svc-digital-twin",
            "svc-pipelines",
            "svc-dataset-api",
            "svc-nudging",
            "svc-rec-registry",
            "svc-flexibility",
            "svc-grid",
            "svc-webapp",
            "svc-forecast",
            "celine-cli",
        ]:
            assert expected in client_ids, f"Existing client '{expected}' missing"
