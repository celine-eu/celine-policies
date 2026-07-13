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


class TestClientsYamlDataspaceEntries:
    def test_parses_without_error(self):
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)
        assert len(config.clients) > 0
        assert len(config.scopes) > 0

    def test_identity_registry_admin_scope_defined(self):
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)
        scope_names = config.get_scope_names()
        assert "identity-registry.admin" in scope_names

    def test_ds_identity_registry_client(self):
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)
        client_ids = config.get_client_ids()
        assert "svc-ds-identity-registry" in client_ids
        ir = next(c for c in config.clients if c.client_id == "svc-ds-identity-registry")
        assert ir.scopes_prefix == "identity-registry"
        assert "identity-registry.admin" in ir.default_scopes

    def test_ds_onboarding_client(self):
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)
        client_ids = config.get_client_ids()
        assert "svc-ds-onboarding" in client_ids
        ob = next(c for c in config.clients if c.client_id == "svc-ds-onboarding")
        assert "identity-registry.admin" in ob.default_scopes
        assert "svc-ds-identity-registry" in ob.extra_audiences

    def test_ds_portal_client(self):
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)
        client_ids = config.get_client_ids()
        assert "svc-ds-portal" in client_ids
        portal = next(c for c in config.clients if c.client_id == "svc-ds-portal")
        assert portal.service_account_enabled is False
        assert "dataset.query" in portal.default_scopes
        assert "dataset.read" in portal.default_scopes

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
