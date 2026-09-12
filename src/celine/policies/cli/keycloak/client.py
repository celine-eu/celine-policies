"""Keycloak Admin API client.

Wraps the Keycloak Admin REST API for managing:
- Client scopes
- Clients
- Scope-to-client assignments
- Service account roles
- Protocol mappers (audience mappers for cross-service calls)
- Users and group memberships
"""

from __future__ import annotations

import asyncio
import json as jsonlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from celine.policies.cli.keycloak.settings import KeycloakSettings

logger = logging.getLogger(__name__)

# Name prefix used to tag audience mappers managed by this CLI.
# This lets us reliably identify and diff our mappers vs. manually created ones.
AUDIENCE_MAPPER_PREFIX = "aud-"

# Standard role hierarchy used at both realm and organisation level.
# Order: most-privileged first.
ROLE_HIERARCHY: list[str] = ["admins", "managers", "editors", "viewers"]

# Name prefix on every admin permission and policy this CLI manages, and the
# same sentinel discipline as AUDIENCE_MAPPER_PREFIX: the plan reads and writes
# only names that start with it, so a permission somebody created by hand in the
# admin console is never diffed, narrowed or deleted by a sync.
ADMIN_PERMISSION_PREFIX = "celine-policies:"


def admin_permission_name(client_id: str, group_path: str) -> str:
    """The managed name of the permission granting `client_id` rights on a group."""
    return f"{ADMIN_PERMISSION_PREFIX}{client_id}:group:{group_path.lstrip('/')}"


# Clients Keycloak owns, which `clients.yaml` therefore never declares. They are
# filtered out of the current state so they cannot land in `orphan_clients`,
# where `--prune` would delete them.
#
# `admin-permissions` is the one with teeth: Keycloak creates it when admin
# permissions are enabled, and it is the resource server holding every
# permission this tool grants. Pruning it would take them all with it.
UNMANAGED_KEYCLOAK_CLIENT_IDS = frozenset(
    {
        "admin-cli",
        "broker",
        "realm-management",
        "security-admin-console",
        "admin-permissions",
    }
)


def admin_policy_name(client_id: str) -> str:
    """The managed name of the policy that says 'the caller is this client'.

    One per client rather than one per permission: it is the same assertion
    every time, and Keycloak refuses two policies with the same name anyway.
    """
    return f"{ADMIN_PERMISSION_PREFIX}client:{client_id}"


class KeycloakError(Exception):
    """Base exception for Keycloak API errors."""

    def __init__(
        self, message: str, status_code: int | None = None, response: dict | None = None
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class KeycloakAuthError(KeycloakError):
    """Authentication failed."""

    pass


class KeycloakNotFoundError(KeycloakError):
    """Resource not found."""

    pass


class KeycloakConflictError(KeycloakError):
    """Resource already exists."""

    pass


@dataclass
class TokenInfo:
    """OAuth token information."""

    access_token: str
    expires_at: float
    refresh_token: str | None = None

    def is_valid(self, leeway: int = 30) -> bool:
        """Check if token is still valid."""
        return time.time() < (self.expires_at - leeway)


@dataclass
class CurrentState:
    """Current state of Keycloak resources."""

    scopes: dict[str, dict[str, Any]] = field(default_factory=dict)
    clients: dict[str, dict[str, Any]] = field(default_factory=dict)
    client_default_scopes: dict[str, set[str]] = field(default_factory=dict)
    client_optional_scopes: dict[str, set[str]] = field(default_factory=dict)

    # Audience mappers currently on each client.
    # Maps client_id -> {audience_client_id -> mapper_id}.
    # Only includes mappers whose name starts with AUDIENCE_MAPPER_PREFIX,
    # so manually created mappers are never touched.
    client_audience_mappers: dict[str, dict[str, str]] = field(default_factory=dict)

    # --- Fine-grained admin permissions -------------------------------------
    #
    # All three stay at their defaults unless the declaration asks for admin
    # permissions: `fetch_current_state` does not go looking otherwise, so a
    # realm that does not use the feature costs no extra requests and can plan
    # no admin-permission action.
    admin_permissions_enabled: bool = False

    # UUID of the realm's `admin-permissions` client. None until the realm has
    # the feature enabled — Keycloak creates the client when the flag is set.
    admin_permissions_client_uuid: str | None = None

    # Managed group permissions currently in the realm, as
    # client_id -> {group_path -> GroupAdminGrantState}. Only permissions whose
    # name starts with ADMIN_PERMISSION_PREFIX appear here.
    admin_group_permissions: dict[str, dict[str, "GroupAdminGrantState"]] = field(
        default_factory=dict
    )

    # --- Realm-wide administration ------------------------------------------
    #
    # Filled only for the clients that declare `realm_management_roles`, and
    # only when something does — like the block above, a realm that does not use
    # the feature costs no extra requests.

    #: Every role the realm-management client offers, which is what makes a
    #: misspelt declaration fatal at plan time rather than a 403 in production.
    #:
    #: **`None` means "not consulted", which is not "the realm has none".** An
    #: empty set would collapse those two, and the collapse has a direction:
    #: every declared role would read as misspelt and a sync that is merely
    #: uninformed would refuse to run. `fetch_realm_management_role_state` sets
    #: it, `compute_sync_plan` validates only when it is set, and a plan built
    #: without it still grants — which is what an empty realm needs anyway.
    available_realm_management_roles: set[str] | None = None

    #: client_id -> the realm-management roles its service account holds today.
    realm_management_roles: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class GroupAdminGrantState:
    """One managed group permission as it currently stands in Keycloak."""

    permission_id: str
    scopes: set[str]
    #: The group this permission resolves to, or None when the permission names
    #: a group that has since been deleted.
    group_id: str | None = None


class KeycloakAdminClient:
    """Async client for Keycloak Admin REST API."""

    # Roles required on realm-management for celine-admin-cli to operate.
    # Covers: client/scope sync, user provisioning, group management.
    REQUIRED_REALM_MGMT_ROLES = [
        "manage-clients",
        "manage-realm",
        "view-clients",
        "view-realm",
        "manage-users",
        "view-users",
        "query-groups",
        "query-users",
    ]

    # Well-known Keycloak built-in scopes to ignore during sync.
    # 'organization', 'groups', and 'dataspace' are managed via
    # ensure_*_client_scope() helpers rather than through clients.yaml —
    # exclude from orphan detection.
    BUILTIN_SCOPES = {
        "openid",
        "profile",
        "email",
        "address",
        "phone",
        "offline_access",
        "microprofile-jwt",
        "acr",
        "roles",
        "web-origins",
        "basic",
        "organization",
        "groups",
        "dataspace",
        "service_account",
    }

    def __init__(self, settings: KeycloakSettings):
        self._settings = settings
        self._token: TokenInfo | None = None
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "KeycloakAdminClient":
        """Async context manager entry."""
        self._client = httpx.AsyncClient(timeout=self._settings.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def settings(self) -> KeycloakSettings:
        """Get settings."""
        return self._settings

    # -------------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------------

    async def authenticate(self) -> None:
        """Authenticate and obtain access token.

        Tries service client credentials first, falls back to admin user/pass.
        """
        if self._settings.has_client_credentials:
            await self._authenticate_client_credentials()
        elif self._settings.has_admin_credentials:
            await self._authenticate_admin_user()
        else:
            raise KeycloakAuthError(
                "No credentials provided. Use --admin-client-id/--admin-client-secret "
                "or --admin-user/--admin-password"
            )

    async def _authenticate_client_credentials(self) -> None:
        """Authenticate using client credentials flow."""
        token_url = f"{self._settings.realm_url}/protocol/openid-connect/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": self._settings.admin_client_id,
            "client_secret": self._settings.admin_client_secret,
        }

        logger.debug(
            "Authenticating with client credentials: %s", self._settings.admin_client_id
        )

        response = await self._client.post(token_url, data=data)

        if response.status_code != 200:
            raise KeycloakAuthError(
                f"Client credentials authentication failed: {response.text}",
                status_code=response.status_code,
            )

        payload = response.json()
        self._token = TokenInfo(
            access_token=payload["access_token"],
            expires_at=time.time() + float(payload.get("expires_in", 300)),
            refresh_token=payload.get("refresh_token"),
        )
        logger.info(
            "Authenticated as service client: %s", self._settings.admin_client_id
        )

    async def _authenticate_admin_user(self) -> None:
        """Authenticate using admin user credentials (master realm)."""
        token_url = f"{self._settings.master_realm_url}/protocol/openid-connect/token"

        data = {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": self._settings.admin_user,
            "password": self._settings.admin_password,
        }

        logger.debug("Authenticating with admin user: %s", self._settings.admin_user)

        response = await self._client.post(token_url, data=data)

        if response.status_code != 200:
            raise KeycloakAuthError(
                f"Admin user authentication failed: {response.text}",
                status_code=response.status_code,
            )

        payload = response.json()
        self._token = TokenInfo(
            access_token=payload["access_token"],
            expires_at=time.time() + float(payload.get("expires_in", 300)),
            refresh_token=payload.get("refresh_token"),
        )
        logger.info("Authenticated as admin user: %s", self._settings.admin_user)

    async def _ensure_token(self) -> str:
        """Ensure we have a valid token."""
        if not self._token or not self._token.is_valid():
            await self.authenticate()
        return self._token.access_token

    async def _headers(self) -> dict[str, str]:
        """Get request headers with auth token."""
        token = await self._ensure_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    # -------------------------------------------------------------------------
    # HTTP helpers
    # -------------------------------------------------------------------------

    async def _get(self, path: str) -> Any:
        """Make GET request to admin API."""
        url = f"{self._settings.admin_url}{path}"
        headers = await self._headers()
        response = await self._client.get(url, headers=headers)
        return self._handle_response(response)

    async def _post(self, path: str, json: list | dict | str | None = None) -> Any:
        """Make POST request to admin API."""
        url = f"{self._settings.admin_url}{path}"
        headers = await self._headers()
        response = await self._client.post(url, headers=headers, json=json)
        return self._handle_response(response, expected_status=[200, 201, 204])

    async def _put(
        self,
        path: str,
        json: dict | None = None,
        expected_status: list[int] | None = None,
    ) -> Any:
        """Make PUT request to admin API.

        `expected_status` widens the accepted set for the endpoints that do not
        answer a PUT with 200 or 204 — the authorization services answer one
        with 201, the same as a create.
        """
        url = f"{self._settings.admin_url}{path}"
        headers = await self._headers()
        response = await self._client.put(url, headers=headers, json=json)
        return self._handle_response(
            response, expected_status=expected_status or [200, 204]
        )

    async def _delete(self, path: str) -> Any:
        """Make DELETE request to admin API."""
        url = f"{self._settings.admin_url}{path}"
        headers = await self._headers()
        response = await self._client.delete(url, headers=headers)
        return self._handle_response(response, expected_status=[200, 204])

    def _handle_response(
        self,
        response: httpx.Response,
        expected_status: list[int] | None = None,
    ) -> Any:
        """Handle API response."""
        expected = expected_status or [200]

        if response.status_code == 404:
            raise KeycloakNotFoundError(
                f"Resource not found: {response.request.url}",
                status_code=404,
            )

        if response.status_code == 409:
            raise KeycloakConflictError(
                f"Resource already exists: {response.text}",
                status_code=409,
            )

        if response.status_code == 401:
            raise KeycloakAuthError(
                "Authentication expired or invalid",
                status_code=401,
            )

        if response.status_code not in expected:
            raise KeycloakError(
                f"Unexpected response {response.status_code}: {response.text}",
                status_code=response.status_code,
            )

        if response.status_code == 204 or not response.content:
            return None

        return response.json()

    # -------------------------------------------------------------------------
    # Client Scopes
    # -------------------------------------------------------------------------

    async def list_client_scopes(self) -> list[dict[str, Any]]:
        """List all client scopes in the realm."""
        return await self._get("/client-scopes")

    async def get_client_scope(self, scope_id: str) -> dict[str, Any]:
        """Get a client scope by ID."""
        return await self._get(f"/client-scopes/{scope_id}")

    async def get_client_scope_by_name(self, name: str) -> dict[str, Any] | None:
        """Get a client scope by name."""
        scopes = await self.list_client_scopes()
        for scope in scopes:
            if scope.get("name") == name:
                return scope
        return None

    async def create_client_scope(
        self,
        name: str,
        description: str = "",
        protocol: str = "openid-connect",
        include_in_token_scope: bool = True,
    ) -> str:
        """Create a new client scope. Returns the scope ID."""
        payload = {
            "name": name,
            "description": description,
            "protocol": protocol,
            "attributes": {
                "include.in.token.scope": str(include_in_token_scope).lower(),
                "display.on.consent.screen": "true",
            },
        }

        logger.debug("Creating client scope: %s", name)
        await self._post("/client-scopes", json=payload)

        scope = await self.get_client_scope_by_name(name)
        if not scope:
            raise KeycloakError(f"Failed to retrieve created scope: {name}")

        logger.info("Created client scope: %s (id=%s)", name, scope["id"])
        return scope["id"]

    async def update_client_scope(
        self,
        scope_id: str,
        name: str,
        description: str = "",
        protocol: str = "openid-connect",
        include_in_token_scope: bool = True,
    ) -> None:
        """Update an existing client scope."""
        payload = {
            "id": scope_id,
            "name": name,
            "description": description,
            "protocol": protocol,
            "attributes": {
                "include.in.token.scope": str(include_in_token_scope).lower(),
                "display.on.consent.screen": "true",
            },
        }

        logger.debug("Updating client scope: %s", name)
        await self._put(f"/client-scopes/{scope_id}", json=payload)
        logger.info("Updated client scope: %s", name)

    async def get_scope_protocol_mappers(self, scope_id: str) -> list[dict[str, Any]]:
        """List all protocol mappers for a client scope."""
        return (
            await self._get(f"/client-scopes/{scope_id}/protocol-mappers/models") or []
        )

    async def update_scope_protocol_mapper(
        self, scope_id: str, mapper: dict[str, Any]
    ) -> None:
        """Update an existing protocol mapper on a client scope."""
        await self._put(
            f"/client-scopes/{scope_id}/protocol-mappers/models/{mapper['id']}",
            json=mapper,
        )

    async def ensure_org_client_scope(self) -> tuple[str, bool]:
        """Ensure the 'organization' client scope exists with its required mappers.

        Manages two mappers on the scope (per KC docs — both are required for
        org group membership to appear in tokens):
          1. oidc-organization-membership-mapper  → 'organization' claim with attributes
          2. oidc-organization-group-membership-mapper → adds 'groups' key inside
             each org entry in the 'organization' claim

        Creates/updates either mapper if absent or config drifts.
        Returns (scope_id, changed).
        """
        changed = False

        scope = await self.get_client_scope_by_name("organization")
        if not scope:
            scope_id = await self.create_client_scope(
                name="organization",
                description="Organization membership claims",
            )
            changed = True
            logger.info("Created 'organization' client scope (%s)", scope_id)
        else:
            scope_id = scope["id"]

        mappers = await self.get_scope_protocol_mappers(scope_id)

        # --- mapper 1: organization membership ---
        DESIRED_MEMBERSHIP = {
            "introspection.token.claim": "true",
            "multivalued": "true",
            "userinfo.token.claim": "true",
            "addOrganizationAttributes": "true",
            "id.token.claim": "true",
            "lightweight.claim": "false",
            "access.token.claim": "true",
            "claim.name": "organization",
            "jsonType.label": "JSON",
            "addOrganizationId": "false",
        }
        existing_membership = next(
            (m for m in mappers if m.get("protocolMapper") == "oidc-organization-membership-mapper"),
            None,
        )
        if existing_membership:
            config = existing_membership.get("config", {})
            if any(config.get(k) != v for k, v in DESIRED_MEMBERSHIP.items()):
                config.update(DESIRED_MEMBERSHIP)
                existing_membership["config"] = config
                await self.update_scope_protocol_mapper(scope_id, existing_membership)
                logger.info("Updated organization membership mapper on scope %s", scope_id)
                changed = True
        else:
            await self._post(
                f"/client-scopes/{scope_id}/protocol-mappers/models",
                json={
                    "name": "organization",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-organization-membership-mapper",
                    "consentRequired": False,
                    "config": DESIRED_MEMBERSHIP,
                },
            )
            logger.info("Added organization membership mapper to scope %s", scope_id)
            changed = True

        # --- mapper 2: organization group membership ---
        # Adds a 'groups' key inside each org entry so org group membership appears
        # in the token. Requires the membership mapper above to also be present.
        DESIRED_GROUPS = {
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
            "introspection.token.claim": "true",
            "lightweight.claim": "false",
        }
        existing_groups = next(
            (m for m in mappers if m.get("protocolMapper") == "oidc-organization-group-membership-mapper"),
            None,
        )
        if existing_groups:
            config = existing_groups.get("config", {})
            if any(config.get(k) != v for k, v in DESIRED_GROUPS.items()):
                config.update(DESIRED_GROUPS)
                existing_groups["config"] = config
                await self.update_scope_protocol_mapper(scope_id, existing_groups)
                logger.info("Updated organization group membership mapper on scope %s", scope_id)
                changed = True
        else:
            await self._post(
                f"/client-scopes/{scope_id}/protocol-mappers/models",
                json={
                    "name": "organization group membership",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-organization-group-membership-mapper",
                    "consentRequired": False,
                    "config": DESIRED_GROUPS,
                },
            )
            logger.info("Added organization group membership mapper to scope %s", scope_id)
            changed = True

        return scope_id, changed

    # -------------------------------------------------------------------------
    # Realm-level claim scopes (groups, organization)
    #
    # These scopes carry OIDC claim mappers (groups, org membership).
    # Policy: realm Assigned type = None (not auto-applied to every client),
    # explicitly assigned as Default on the oauth2_proxy client only.
    #
    # Single entry point: ensure_realm_claim_scopes(oauth2_proxy_client_id).
    # Call it from any command that needs realm claim scopes to be correct —
    # idempotent, safe to call multiple times from different commands.
    # -------------------------------------------------------------------------

    async def _get_realm_default_client_scopes(self) -> list[dict[str, Any]]:
        return await self._get("/default-default-client-scopes") or []

    async def _get_realm_optional_client_scopes(self) -> list[dict[str, Any]]:
        return await self._get("/default-optional-client-scopes") or []

    async def _ensure_scope_not_realm_default(self, scope_id: str, name: str) -> bool:
        """Remove scope from realm default/optional lists (Assigned type → None).

        Returns True if anything was removed.
        """
        changed = False
        defaults = await self._get_realm_default_client_scopes()
        if any(s.get("id") == scope_id for s in defaults):
            await self._delete(f"/default-default-client-scopes/{scope_id}")
            logger.info("Removed '%s' from realm-level default client scopes", name)
            changed = True
        optionals = await self._get_realm_optional_client_scopes()
        if any(s.get("id") == scope_id for s in optionals):
            await self._delete(f"/default-optional-client-scopes/{scope_id}")
            logger.info("Removed '%s' from realm-level optional client scopes", name)
            changed = True
        return changed

    async def _ensure_scope_default_on_client(
        self, client_uuid: str, scope_name: str
    ) -> bool:
        """Ensure a named scope is assigned as Default on a client.

        Returns True if it was just assigned.
        """
        current = await self.get_client_default_scopes(client_uuid)
        if any(s.get("name") == scope_name for s in current):
            logger.debug("'%s' already a default scope on client %s", scope_name, client_uuid)
            return False
        scope = await self.get_client_scope_by_name(scope_name)
        if not scope:
            raise KeycloakError(f"Scope '{scope_name}' not found in realm")
        await self.add_client_default_scope(client_uuid, scope["id"])
        logger.info("Assigned '%s' as default scope on client %s", scope_name, client_uuid)
        return True

    async def _ensure_groups_client_scope(self) -> tuple[str, bool]:
        """Ensure the 'groups' client scope exists with its group membership mapper.

        Creates scope and/or mapper if absent; updates mapper config on drift.
        Does NOT set realm-level assignment — caller decides Default/Optional/None.
        Returns (scope_id, changed).
        """
        DESIRED = {
            "claim.name": "groups",
            "full.path": "true",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
            "introspection.token.claim": "true",
        }
        changed = False

        scope = await self.get_client_scope_by_name("groups")
        if not scope:
            scope_id = await self.create_client_scope(
                name="groups", description="Group membership claims"
            )
            changed = True
            logger.info("Created 'groups' client scope (%s)", scope_id)
        else:
            scope_id = scope["id"]

        mappers = await self.get_scope_protocol_mappers(scope_id)
        existing = next(
            (m for m in mappers if m.get("protocolMapper") == "oidc-group-membership-mapper"),
            None,
        )
        if existing:
            config = existing.get("config", {})
            if any(config.get(k) != v for k, v in DESIRED.items()):
                config.update(DESIRED)
                existing["config"] = config
                await self.update_scope_protocol_mapper(scope_id, existing)
                logger.info("Updated groups mapper on scope %s", scope_id)
                changed = True
        else:
            await self._post(
                f"/client-scopes/{scope_id}/protocol-mappers/models",
                json={
                    "name": "groups",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-group-membership-mapper",
                    "consentRequired": False,
                    "config": DESIRED,
                },
            )
            logger.info("Added groups mapper to scope %s", scope_id)
            changed = True

        return scope_id, changed

    async def _ensure_dataspace_claim_scope(self) -> tuple[str, bool]:
        """Ensure the 'dataspace' client scope exists with its DID attribute mapper.

        Creates a ``dataspace`` scope with an ``oidc-usermodel-attribute-mapper``
        that exposes the ``dataspace_did`` user attribute as a JWT claim.

        Backward compatible: if a user has no ``dataspace_did`` attribute the
        claim is simply absent from the JWT — no breakage for non-dataspace setups.

        Returns (scope_id, changed).
        """
        DESIRED = {
            "claim.name": "dataspace_did",
            "user.attribute": "dataspace_did",
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
        }
        changed = False

        scope = await self.get_client_scope_by_name("dataspace")
        if not scope:
            scope_id = await self.create_client_scope(
                name="dataspace", description="Dataspace DID claims"
            )
            changed = True
            logger.info("Created 'dataspace' client scope (%s)", scope_id)
        else:
            scope_id = scope["id"]

        mappers = await self.get_scope_protocol_mappers(scope_id)
        existing = next(
            (m for m in mappers if m.get("name") == "dataspace-did"),
            None,
        )
        if existing:
            config = existing.get("config", {})
            if any(config.get(k) != v for k, v in DESIRED.items()):
                config.update(DESIRED)
                existing["config"] = config
                await self.update_scope_protocol_mapper(scope_id, existing)
                logger.info("Updated dataspace-did mapper on scope %s", scope_id)
                changed = True
        else:
            await self._post(
                f"/client-scopes/{scope_id}/protocol-mappers/models",
                json={
                    "name": "dataspace-did",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "consentRequired": False,
                    "config": DESIRED,
                },
            )
            logger.info("Added dataspace-did mapper to scope %s", scope_id)
            changed = True

        return scope_id, changed

    async def ensure_realm_claim_scopes(
        self, oauth2_proxy_client_id: str | None = None
    ) -> bool:
        """Idempotently provision realm-level claim scopes (organization, groups, dataspace).

        For each scope:
          1. Ensure the scope + protocol mapper exist (create/update on drift)
          2. Set realm Assigned type = None (remove from realm defaults/optionals)
          3. Assign as Default on the oauth2_proxy client (if provided and found)

        Safe to call from any command (sync, sync-users, etc.) — all paths
        converge to the same desired state.

        Returns True if anything was created or updated.
        """
        changed = False

        # --- organization scope ---
        org_id, c = await self.ensure_org_client_scope()
        changed = changed or c
        c = await self._ensure_scope_not_realm_default(org_id, "organization")
        changed = changed or c

        # --- groups scope ---
        groups_id, c = await self._ensure_groups_client_scope()
        changed = changed or c
        c = await self._ensure_scope_not_realm_default(groups_id, "groups")
        changed = changed or c

        # --- dataspace scope ---
        ds_id, c = await self._ensure_dataspace_claim_scope()
        changed = changed or c
        c = await self._ensure_scope_not_realm_default(ds_id, "dataspace")
        changed = changed or c

        # --- assign all three as Default on oauth2_proxy ---
        if oauth2_proxy_client_id:
            proxy = await self.get_client_by_client_id(oauth2_proxy_client_id)
            if proxy:
                proxy_uuid = proxy["id"]
                c = await self._ensure_scope_default_on_client(proxy_uuid, "organization")
                changed = changed or c
                c = await self._ensure_scope_default_on_client(proxy_uuid, "groups")
                changed = changed or c
                c = await self._ensure_scope_default_on_client(proxy_uuid, "dataspace")
                changed = changed or c
            else:
                logger.warning(
                    "Client '%s' not found — skipping claim scope assignment",
                    oauth2_proxy_client_id,
                )

        return changed

    async def delete_client_scope(self, scope_id: str) -> None:
        """Delete a client scope."""
        logger.debug("Deleting client scope: %s", scope_id)
        await self._delete(f"/client-scopes/{scope_id}")
        logger.info("Deleted client scope: %s", scope_id)

    # -------------------------------------------------------------------------
    # Clients
    # -------------------------------------------------------------------------

    async def list_clients(self) -> list[dict[str, Any]]:
        """List all clients in the realm."""
        return await self._get("/clients")

    async def get_client(self, client_uuid: str) -> dict[str, Any]:
        """Get a client by UUID."""
        return await self._get(f"/clients/{client_uuid}")

    async def get_client_by_client_id(self, client_id: str) -> dict[str, Any] | None:
        """Get a client by clientId."""
        clients = await self._get(f"/clients?clientId={client_id}")
        if clients:
            return clients[0]
        return None

    async def create_client(
        self,
        client_id: str,
        name: str = "",
        description: str = "",
        secret: str | None = None,
        service_account_enabled: bool = True,
    ) -> tuple[str, str]:
        """Create a new client with client credentials grant.

        Returns tuple of (client_uuid, client_secret).
        """
        payload = {
            "clientId": client_id,
            "name": name or client_id,
            "description": description,
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "serviceAccountsEnabled": service_account_enabled,
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "clientAuthenticatorType": "client-secret",
        }

        if secret:
            payload["secret"] = secret

        logger.debug("Creating client: %s", client_id)
        await self._post("/clients", json=payload)

        client = await self.get_client_by_client_id(client_id)
        if not client:
            raise KeycloakError(f"Failed to retrieve created client: {client_id}")

        client_uuid = client["id"]
        actual_secret = await self.get_client_secret(client_uuid)

        logger.info("Created client: %s (uuid=%s)", client_id, client_uuid)
        return client_uuid, actual_secret

    async def update_client(
        self,
        client_uuid: str,
        client_id: str,
        name: str = "",
        description: str = "",
        service_account_enabled: bool = True,
        secret: str | None = None,
    ) -> None:
        """Update an existing client."""
        current = await self.get_client(client_uuid)

        payload = {
            **current,
            "clientId": client_id,
            "name": name or client_id,
            "description": description,
            "serviceAccountsEnabled": service_account_enabled,
            "publicClient": False,
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
        }

        if secret:
            payload["secret"] = secret

        logger.debug("Updating client: %s", client_id)
        await self._put(f"/clients/{client_uuid}", json=payload)
        logger.info("Updated client: %s", client_id)

    async def delete_client(self, client_uuid: str) -> None:
        """Delete a client."""
        logger.debug("Deleting client: %s", client_uuid)
        await self._delete(f"/clients/{client_uuid}")
        logger.info("Deleted client: %s", client_uuid)

    async def get_client_secret(self, client_uuid: str) -> str:
        """Get the client secret."""
        result = await self._get(f"/clients/{client_uuid}/client-secret")
        return result.get("value", "")

    async def regenerate_client_secret(self, client_uuid: str) -> str:
        """Regenerate the client secret."""
        logger.debug("Regenerating client secret for: %s", client_uuid)
        result = await self._post(f"/clients/{client_uuid}/client-secret")
        return result.get("value", "")

    # -------------------------------------------------------------------------
    # Client Scope Assignments
    # -------------------------------------------------------------------------

    async def get_client_default_scopes(self, client_uuid: str) -> list[dict[str, Any]]:
        """Get default scopes assigned to a client."""
        return await self._get(f"/clients/{client_uuid}/default-client-scopes")

    async def get_client_optional_scopes(
        self, client_uuid: str
    ) -> list[dict[str, Any]]:
        """Get optional scopes assigned to a client."""
        return await self._get(f"/clients/{client_uuid}/optional-client-scopes")

    async def add_client_default_scope(self, client_uuid: str, scope_id: str) -> None:
        """Add a default scope to a client."""
        logger.debug("Adding default scope %s to client %s", scope_id, client_uuid)
        await self._put(f"/clients/{client_uuid}/default-client-scopes/{scope_id}")

    async def remove_client_default_scope(
        self, client_uuid: str, scope_id: str
    ) -> None:
        """Remove a default scope from a client."""
        logger.debug("Removing default scope %s from client %s", scope_id, client_uuid)
        await self._delete(f"/clients/{client_uuid}/default-client-scopes/{scope_id}")

    async def add_client_optional_scope(self, client_uuid: str, scope_id: str) -> None:
        """Add an optional scope to a client."""
        logger.debug("Adding optional scope %s to client %s", scope_id, client_uuid)
        await self._put(f"/clients/{client_uuid}/optional-client-scopes/{scope_id}")

    async def remove_client_optional_scope(
        self, client_uuid: str, scope_id: str
    ) -> None:
        """Remove an optional scope from a client."""
        logger.debug("Removing optional scope %s from client %s", scope_id, client_uuid)
        await self._delete(f"/clients/{client_uuid}/optional-client-scopes/{scope_id}")

    async def ensure_default_scope(self, client_uuid: str, scope_name: str) -> None:
        """Ensure a named scope is in the client's default scopes.

        Idempotent: no-op if already assigned.
        Raises KeycloakError if the scope doesn't exist in the realm.
        """
        current = await self.get_client_default_scopes(client_uuid)
        if any(s.get("name") == scope_name for s in current):
            logger.info("Scope '%s' already in default scopes — skipping", scope_name)
            return

        scope = await self.get_client_scope_by_name(scope_name)
        if not scope:
            raise KeycloakError(
                f"Scope '{scope_name}' not found in realm. "
                f"Cannot assign it as a default scope."
            )

        await self.add_client_default_scope(client_uuid, scope["id"])
        logger.info(
            "Added '%s' to default scopes of client %s", scope_name, client_uuid
        )

    # -------------------------------------------------------------------------
    # Protocol Mappers (Audience)
    # -------------------------------------------------------------------------

    async def get_client_protocol_mappers(
        self, client_uuid: str
    ) -> list[dict[str, Any]]:
        """Get all protocol mappers for a client."""
        return await self._get(f"/clients/{client_uuid}/protocol-mappers/models")

    async def create_audience_mapper(
        self,
        client_uuid: str,
        audience_client_id: str,
    ) -> str:
        """Add a hardcoded audience mapper to a client.

        The mapper name follows the AUDIENCE_MAPPER_PREFIX convention so the
        CLI can distinguish its own mappers from manually created ones.

        Returns the mapper ID.
        """
        mapper_name = f"{AUDIENCE_MAPPER_PREFIX}{audience_client_id}"
        payload = {
            "name": mapper_name,
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.client.audience": audience_client_id,
                "id.token.claim": "false",
                "access.token.claim": "true",
            },
        }

        logger.debug(
            "Adding audience mapper '%s' to client %s", mapper_name, client_uuid
        )
        result = await self._post(
            f"/clients/{client_uuid}/protocol-mappers/models", json=payload
        )

        if result and isinstance(result, dict):
            mapper_id = result.get("id", "")
        else:
            mappers = await self.get_client_protocol_mappers(client_uuid)
            mapper_id = next(
                (m["id"] for m in mappers if m.get("name") == mapper_name), ""
            )

        logger.info(
            "Created audience mapper '%s' on client %s (id=%s)",
            mapper_name,
            client_uuid,
            mapper_id,
        )
        return mapper_id

    async def ensure_audience_mapper(
        self, client_uuid: str, audience_client_id: str
    ) -> bool:
        """Ensure a hardcoded audience mapper exists on a client.

        Idempotent — no-op if a mapper with the expected name already exists.
        Returns True if the mapper was just created.
        """
        mapper_name = f"{AUDIENCE_MAPPER_PREFIX}{audience_client_id}"
        mappers = await self.get_client_protocol_mappers(client_uuid)
        if any(m.get("name") == mapper_name for m in mappers):
            logger.info("Audience mapper '%s' already present — skipping", mapper_name)
            return False
        await self.create_audience_mapper(client_uuid, audience_client_id)
        return True

    async def delete_protocol_mapper(self, client_uuid: str, mapper_id: str) -> None:
        """Delete a protocol mapper from a client."""
        logger.debug(
            "Deleting protocol mapper %s from client %s", mapper_id, client_uuid
        )
        await self._delete(
            f"/clients/{client_uuid}/protocol-mappers/models/{mapper_id}"
        )
        logger.info("Deleted protocol mapper %s from client %s", mapper_id, client_uuid)

    # -------------------------------------------------------------------------
    # Service Account / Bootstrap helpers
    # -------------------------------------------------------------------------

    async def get_service_account_user(self, client_uuid: str) -> dict[str, Any]:
        """Get the service account user for a client."""
        return await self._get(f"/clients/{client_uuid}/service-account-user")

    async def get_realm_management_client(self) -> dict[str, Any] | None:
        """Get the realm-management client."""
        return await self.get_client_by_client_id("realm-management")

    async def get_client_roles(self, client_uuid: str) -> list[dict[str, Any]]:
        """Get all roles for a client."""
        return await self._get(f"/clients/{client_uuid}/roles")

    async def get_user_client_roles(
        self, user_id: str, client_uuid: str
    ) -> list[dict[str, Any]]:
        """Get client roles currently assigned to a user."""
        return await self._get(f"/users/{user_id}/role-mappings/clients/{client_uuid}")

    async def assign_client_roles_to_user(
        self,
        user_id: str,
        client_uuid: str,
        roles: list[dict[str, Any]],
    ) -> None:
        """Assign client roles to a user."""
        logger.debug("Assigning %d roles to user %s", len(roles), user_id)
        await self._post(
            f"/users/{user_id}/role-mappings/clients/{client_uuid}",
            json=roles,
        )

    async def ensure_realm_management_audience_mapper(self, client_uuid: str) -> None:
        """Ensure the client token includes realm-management in its audience.

        Without this mapper, Keycloak won't surface the realm-management role
        mappings in the token — resource_access will be empty and every Admin
        API call returns 403, even if the service account has the roles.

        Idempotent: checks for an existing mapper before creating.
        """
        mapper_name = "realm-management-audience"

        mappers = await self.get_client_protocol_mappers(client_uuid)
        existing = next((m for m in mappers if m.get("name") == mapper_name), None)
        if existing:
            logger.info("realm-management audience mapper already present — skipping")
            return

        payload = {
            "name": mapper_name,
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.client.audience": "realm-management",
                "id.token.claim": "false",
                "access.token.claim": "true",
            },
        }

        logger.info("Adding realm-management audience mapper to client %s", client_uuid)
        await self._post(
            f"/clients/{client_uuid}/protocol-mappers/models", json=payload
        )
        logger.info("realm-management audience mapper created")

    async def assign_realm_management_roles(
        self, client_uuid: str, roles: "list[str] | None" = None
    ) -> None:
        """Ensure the service account holds the named realm-management roles.

        `roles` defaults to `REQUIRED_REALM_MGMT_ROLES`, which is what
        `bootstrap` grants the admin CLI. A caller passing its own list is a
        client declaring `realm_management_roles` — see ADR-0007 — and gets
        exactly what it declared and nothing else.

        **Additive.** A role the account holds and the list does not name is
        left alone: this method cannot tell a role it granted from one an
        operator granted by hand, and the classic model has no sentinel to tell
        it with. Revoking realm administration is a deliberate act, done where
        it can be seen.

        Idempotent: fetches currently assigned roles first and only assigns
        what is missing. Raises if any named role is missing or cannot be
        verified after assignment.
        """
        wanted = list(roles) if roles is not None else list(self.REQUIRED_REALM_MGMT_ROLES)

        sa_user = await self.get_service_account_user(client_uuid)
        user_id = sa_user["id"]

        rm_client = await self.get_realm_management_client()
        if not rm_client:
            raise KeycloakError("realm-management client not found")
        rm_client_uuid = rm_client["id"]

        all_roles = await self.get_client_roles(rm_client_uuid)
        role_map = {r["name"]: r for r in all_roles}

        for role_name in wanted:
            if role_name not in role_map:
                raise KeycloakError(
                    f"Required role '{role_name}' not found in realm-management. "
                    f"Available: {sorted(role_map.keys())}"
                )

        current_roles = await self.get_user_client_roles(user_id, rm_client_uuid)
        current_role_names = {r["name"] for r in current_roles}

        missing_roles = [
            role_map[name] for name in wanted if name not in current_role_names
        ]

        if not missing_roles:
            logger.info(
                "Service account already has all required realm-management roles"
            )
            return

        logger.info(
            "Assigning missing roles to service account: %s",
            [r["name"] for r in missing_roles],
        )
        await self.assign_client_roles_to_user(user_id, rm_client_uuid, missing_roles)

        # Verify assignment succeeded
        assigned_roles = await self.get_user_client_roles(user_id, rm_client_uuid)
        assigned_names = {r["name"] for r in assigned_roles}
        still_missing = [name for name in wanted if name not in assigned_names]
        if still_missing:
            raise KeycloakError(
                f"Role assignment failed — still missing after assign: {still_missing}"
            )

        logger.info(
            "Successfully assigned realm-management roles: %s",
            [r["name"] for r in missing_roles],
        )

    # -------------------------------------------------------------------------
    # Fine-grained admin permissions
    # -------------------------------------------------------------------------
    #
    # Keycloak 26.2 replaced the deprecated fine-grained admin authz with a
    # second version, and on 26.6 — the version keycloak/version.txt pins —
    # ADMIN_FINE_GRAINED_AUTHZ_V2 is a DEFAULT feature and enabled, not a
    # preview. The realm flag creates an `admin-permissions` client whose
    # authorization services hold the whole model:
    #
    #   resource types   Clients, Groups, Roles, Users
    #   a policy         "the caller is client X"
    #   a permission     "on resource R of type T, allow scopes S, per policy P"
    #
    # Turning the flag on does not disturb anything: a service account holding
    # realm-management roles the classic way keeps working exactly as before,
    # which is what makes this safe to apply to a realm already in service.

    async def get_admin_permissions_client_uuid(self) -> str | None:
        """UUID of the realm's `admin-permissions` client, or None if disabled.

        Read off the realm representation rather than looked up by client id:
        Keycloak reports it there, and a client called `admin-permissions` that
        the realm does not point at is not the resource server.
        """
        realm = await self.get_realm_settings()
        if not realm.get("adminPermissionsEnabled"):
            return None
        return (realm.get("adminPermissionsClient") or {}).get("id")

    async def ensure_admin_permissions_enabled(self) -> tuple[str, bool]:
        """Enable admin permissions on the realm if needed. Returns (uuid, changed).

        Idempotent, and reversible: setting the flag back to false leaves the
        `admin-permissions` client and every permission under it intact, and
        re-enabling returns the same uuid.
        """
        existing = await self.get_admin_permissions_client_uuid()
        if existing:
            logger.debug("Admin permissions already enabled (%s)", existing)
            return existing, False

        realm = await self.get_realm_settings()
        realm["adminPermissionsEnabled"] = True
        await self.update_realm_settings(realm)

        uuid = await self.get_admin_permissions_client_uuid()
        if not uuid:
            raise KeycloakError(
                "Enabled adminPermissionsEnabled on the realm but Keycloak reports no "
                "admin-permissions client. The server may be running without the "
                "ADMIN_FINE_GRAINED_AUTHZ_V2 feature."
            )
        logger.info("Enabled fine-grained admin permissions on the realm (%s)", uuid)
        return uuid, True

    async def list_admin_permissions(self, ap_uuid: str) -> list[dict[str, Any]]:
        """Every permission on the admin-permissions resource server."""
        return (
            await self._get(f"/clients/{ap_uuid}/authz/resource-server/permission") or []
        )

    async def get_admin_permission_resources(
        self, ap_uuid: str, permission_id: str
    ) -> list[dict[str, Any]]:
        """Resources a permission applies to.

        Each entry's `name` is the **group id** — Keycloak wraps the group in an
        authorization resource whose own `_id` is something else entirely, so
        the id to diff against a declaration is `name`, not `_id`.
        """
        return (
            await self._get(
                f"/clients/{ap_uuid}/authz/resource-server/policy/{permission_id}/resources"
            )
            or []
        )

    async def get_admin_permission_scopes(
        self, ap_uuid: str, permission_id: str
    ) -> list[dict[str, Any]]:
        """Scopes a permission allows."""
        return (
            await self._get(
                f"/clients/{ap_uuid}/authz/resource-server/policy/{permission_id}/scopes"
            )
            or []
        )

    async def find_admin_policy_by_name(
        self, ap_uuid: str, name: str
    ) -> dict[str, Any] | None:
        """One policy on the admin-permissions resource server, by exact name."""
        policies = (
            await self._get(
                f"/clients/{ap_uuid}/authz/resource-server/policy?name={name}"
            )
            or []
        )
        return next((p for p in policies if p.get("name") == name), None)

    async def ensure_admin_client_policy(
        self, ap_uuid: str, client_id: str, client_uuid: str
    ) -> str:
        """Ensure the 'the caller is this client' policy exists. Returns its id.

        Idempotent. The policy is rewritten when it names the wrong client uuid,
        which is what happens when a client is deleted and recreated: the id
        moves and a policy still naming the old one silently matches nobody.
        """
        name = admin_policy_name(client_id)
        existing = await self.find_admin_policy_by_name(ap_uuid, name)

        if existing:
            if self._policy_client_uuids(existing) == {client_uuid}:
                return existing["id"]
            # Rebuilt rather than spread over `existing`: the listing carries a
            # `config` block that Keycloak will not accept back on a PUT.
            await self._put(
                f"/clients/{ap_uuid}/authz/resource-server/policy/client/{existing['id']}",
                json={
                    "id": existing["id"],
                    "name": name,
                    "type": "client",
                    "logic": existing.get("logic", "POSITIVE"),
                    "decisionStrategy": existing.get(
                        "decisionStrategy", "UNANIMOUS"
                    ),
                    "clients": [client_uuid],
                },
                expected_status=[200, 201, 204],
            )
            logger.info("Repointed admin policy %s at client %s", name, client_uuid)
            return existing["id"]

        created = await self._post(
            f"/clients/{ap_uuid}/authz/resource-server/policy/client",
            json={"name": name, "clients": [client_uuid]},
        )
        logger.info("Created admin policy %s", name)
        return created["id"]

    @staticmethod
    def _policy_client_uuids(policy: dict[str, Any]) -> set[str]:
        """The client uuids a client policy names, in either shape Keycloak uses.

        Fetched on its own, a client policy carries `clients` as a list of
        uuids. The **same policy in a listing** carries them inside `config` as
        a JSON-encoded string instead, and `clients` is absent entirely. Reading
        only the first shape makes every run conclude the policy points at the
        wrong client and rewrite it — which then fails, because the `config`
        block a listing returns is not something the PUT endpoint accepts back.
        """
        direct = policy.get("clients")
        if isinstance(direct, list):
            return {str(c) for c in direct}

        encoded = (policy.get("config") or {}).get("clients")
        if isinstance(encoded, str):
            try:
                decoded = jsonlib.loads(encoded)
            except ValueError:
                return set()
            if isinstance(decoded, list):
                return {str(c) for c in decoded}

        return set()

    async def create_group_admin_permission(
        self,
        ap_uuid: str,
        client_id: str,
        group_path: str,
        group_id: str,
        scopes: list[str],
        policy_id: str,
    ) -> str:
        """Grant a client's service account `scopes` over one group's members."""
        payload = self._group_permission_payload(
            client_id, group_path, group_id, scopes, policy_id
        )
        created = await self._post(
            f"/clients/{ap_uuid}/authz/resource-server/permission/scope", json=payload
        )
        logger.info(
            "Created admin permission %s (%s on %s)",
            payload["name"],
            ", ".join(sorted(scopes)),
            group_path,
        )
        return created["id"]

    async def update_group_admin_permission(
        self,
        ap_uuid: str,
        permission_id: str,
        client_id: str,
        group_path: str,
        group_id: str,
        scopes: list[str],
        policy_id: str,
    ) -> None:
        """Rewrite a managed group permission to match the declaration."""
        payload = self._group_permission_payload(
            client_id, group_path, group_id, scopes, policy_id
        )
        payload["id"] = permission_id
        await self._put(
            f"/clients/{ap_uuid}/authz/resource-server/permission/scope/{permission_id}",
            json=payload,
            expected_status=[200, 201, 204],
        )
        logger.info(
            "Updated admin permission %s to %s on %s",
            payload["name"],
            ", ".join(sorted(scopes)),
            group_path,
        )

    async def delete_admin_permission(self, ap_uuid: str, permission_id: str) -> None:
        """Delete a managed permission."""
        await self._delete(
            f"/clients/{ap_uuid}/authz/resource-server/permission/scope/{permission_id}"
        )
        logger.info("Deleted admin permission %s", permission_id)

    @staticmethod
    def _group_permission_payload(
        client_id: str,
        group_path: str,
        group_id: str,
        scopes: list[str],
        policy_id: str,
    ) -> dict[str, Any]:
        """The body Keycloak wants for a group-scoped admin permission.

        `resources` takes the **group id**; Keycloak creates the authorization
        resource that wraps it on the way in.
        """
        return {
            "name": admin_permission_name(client_id, group_path),
            "description": (
                f"Managed by celine-policies: {client_id} administers {group_path}"
            ),
            "type": "scope",
            "resourceType": "Groups",
            "resources": [group_id],
            "scopes": sorted(scopes),
            "policies": [policy_id],
            "decisionStrategy": "UNANIMOUS",
            "logic": "POSITIVE",
        }

    async def fetch_admin_permission_state(
        self, state: CurrentState, client_ids: set[str]
    ) -> None:
        """Fill in `state`'s admin-permission fields for the clients that declare it.

        Only called when something declares admin permissions, and it reads only
        names carrying ADMIN_PERMISSION_PREFIX — a permission created by hand in
        the console is invisible here and therefore never touched.
        """
        ap_uuid = await self.get_admin_permissions_client_uuid()
        state.admin_permissions_enabled = ap_uuid is not None
        state.admin_permissions_client_uuid = ap_uuid

        if not ap_uuid:
            return

        for permission in await self.list_admin_permissions(ap_uuid):
            name = permission.get("name", "")
            if not name.startswith(ADMIN_PERMISSION_PREFIX):
                continue

            owner, group_path = self._parse_group_permission_name(name)
            if owner is None or group_path is None:
                continue
            # A permission for a client no longer in the declaration is left
            # alone here; `compute_sync_plan` decides what to do about it.
            if owner not in client_ids:
                continue

            permission_id = permission["id"]
            scopes = {
                s["name"]
                for s in await self.get_admin_permission_scopes(ap_uuid, permission_id)
                if s.get("name")
            }
            resources = await self.get_admin_permission_resources(
                ap_uuid, permission_id
            )
            group_id = resources[0].get("name") if resources else None

            state.admin_group_permissions.setdefault(owner, {})[group_path] = (
                GroupAdminGrantState(
                    permission_id=permission_id,
                    scopes=scopes,
                    group_id=group_id,
                )
            )

    async def fetch_realm_management_role_state(
        self, state: CurrentState, client_ids: "set[str]"
    ) -> None:
        """Fill in `state`'s realm-management fields for the clients named.

        Reads the offered role list once, so a declaration naming a role this
        Keycloak does not have is refused at plan time — the same treatment
        ADR-0002 gives a grant naming an undeclared scope, and for the same
        reason: the alternative is a realm that syncs clean and answers 403.

        A client with no service account yet — one this run is about to create —
        simply has no entry, and every role it declares reads as missing.
        """
        rm_client = await self.get_realm_management_client()
        if not rm_client:
            raise KeycloakError("realm-management client not found")
        rm_client_uuid = rm_client["id"]

        state.available_realm_management_roles = {
            r["name"] for r in await self.get_client_roles(rm_client_uuid) if r.get("name")
        }

        for client_id in sorted(client_ids):
            client = await self.get_client_by_client_id(client_id)
            if not client:
                continue
            try:
                sa_user = await self.get_service_account_user(client["id"])
            except KeycloakError:
                logger.debug("Client %s has no service account yet", client_id)
                continue
            held = await self.get_user_client_roles(sa_user["id"], rm_client_uuid)
            state.realm_management_roles[client_id] = {
                r["name"] for r in held if r.get("name")
            }

    @staticmethod
    def _parse_group_permission_name(name: str) -> tuple[str | None, str | None]:
        """Read `<prefix><client_id>:group:<group name>` back into its two parts.

        Returns `(None, None)` for a managed name of any other shape — the
        client policies share the prefix, and so would a future permission over
        some resource type other than a group.
        """
        rest = name[len(ADMIN_PERMISSION_PREFIX) :]
        client_id, separator, group_name = rest.partition(":group:")
        if not separator or not client_id or not group_name:
            return None, None
        return client_id, f"/{group_name}"

    # -------------------------------------------------------------------------
    # State Fetching
    # -------------------------------------------------------------------------

    async def fetch_current_state(self) -> CurrentState:
        """Fetch the current state of all relevant resources."""
        state = CurrentState()

        scopes = await self.list_client_scopes()
        for scope in scopes:
            name = scope.get("name", "")
            if name and name not in self.BUILTIN_SCOPES:
                state.scopes[name] = scope

        clients = await self.list_clients()
        for client in clients:
            client_id = client.get("clientId", "")
            if (
                client_id
                and not client_id.startswith("account")
                and client_id not in UNMANAGED_KEYCLOAK_CLIENT_IDS
            ):
                state.clients[client_id] = client
                client_uuid = client["id"]

                default_scopes = await self.get_client_default_scopes(client_uuid)
                state.client_default_scopes[client_id] = {
                    s["name"] for s in default_scopes if s.get("name")
                }

                optional_scopes = await self.get_client_optional_scopes(client_uuid)
                state.client_optional_scopes[client_id] = {
                    s["name"] for s in optional_scopes if s.get("name")
                }

                mappers = await self.get_client_protocol_mappers(client_uuid)
                state.client_audience_mappers[client_id] = {
                    m["config"]["included.client.audience"]: m["id"]
                    for m in mappers
                    if m.get("name", "").startswith(AUDIENCE_MAPPER_PREFIX)
                    and m.get("protocolMapper") == "oidc-audience-mapper"
                    and m.get("config", {}).get("included.client.audience")
                }

        return state

    # -------------------------------------------------------------------------
    # Users
    # -------------------------------------------------------------------------

    async def get_user_by_id(self, user_id: str) -> "dict[str, Any] | None":
        """Get a Keycloak user by UUID. Returns None if not found."""
        try:
            return await self._get(f"/users/{user_id}")
        except KeycloakNotFoundError:
            return None

    async def get_user_by_username(self, username: str) -> "dict[str, Any] | None":
        """Get a Keycloak user by exact username. Returns None if not found."""
        results = await self._get(f"/users?username={username}&exact=true")
        if results:
            return results[0]
        return None

    async def get_user_by_email(self, email: str) -> "dict[str, Any] | None":
        """Get a Keycloak user by exact email address. Returns None if not found.

        **This is how an account that already exists is found under a username
        this platform did not choose.** Two writers have named accounts here —
        `sync-users` after a member key, `../onboarding` after the address the
        person gave — and a participant who signed up before either convention
        may authenticate as something else entirely. The address is the only
        identifier all three agree on, which is why the provisioning service
        resolves by it and reads the username back rather than deriving one.

        Needs realm-wide user search (`manage-users` or `view-users`); the
        group-scoped grant of ADR-0003 cannot make this call at all, which is
        the whole reason the create-then-scan-on-409 dance exists.

        Returns the first match. Keycloak does not enforce email uniqueness
        unless the realm's `duplicateEmailsAllowed` is false, so a realm that
        allows duplicates can return more than one and this takes the first —
        deliberately, because picking between them is not a decision an
        automated provisioning call should make.
        """
        results = await self._get(f"/users?email={email}&exact=true")
        if results:
            return results[0]
        return None

    async def set_user_enabled(self, user_id: str, enabled: bool) -> bool:
        """Enable or disable an account. Returns whether it changed.

        Disabling is how access is revoked without destroying anything: the
        account, its memberships and its history stay, and re-enabling is one
        call. Deleting a user is not the same act and is not offered here.

        Reads first so a no-op reports as one — a revocation that was already in
        force must not look like a revocation that just happened.
        """
        user = await self.get_user_by_id(user_id)
        if user is None:
            raise KeycloakNotFoundError(f"User not found: {user_id}")
        if bool(user.get("enabled")) == enabled:
            return False

        payload = dict(user)
        payload["enabled"] = enabled
        await self._put(f"/users/{user_id}", json=payload, expected_status=[204])
        logger.info("Set user %s enabled=%s", user_id, enabled)
        return True

    async def ensure_user(
        self,
        username: str,
        *,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        temporary_password: str | None = None,
        enabled: bool = True,
        temporary: bool = True,
        email_verified: bool = False,
    ) -> tuple[str, bool]:
        """Ensure a user exists, creating it if necessary.

        Username is the stable identity. Keycloak assigns its own UUID —
        we never pre-set it. This avoids all UUID mismatch issues.

        Returns:
            (keycloak_uuid, created) where created=True if the user was newly
            created. Always use the returned UUID for subsequent operations.
        """
        existing = await self.get_user_by_username(username)
        if existing:
            logger.debug("User already exists: %s (%s)", username, existing["id"])
            return existing["id"], False

        await self.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            temporary_password=temporary_password,
            enabled=enabled,
            temporary=temporary,
            email_verified=email_verified,
        )

        # Fetch back to get the Keycloak-assigned UUID
        created_user = await self.get_user_by_username(username)
        if not created_user:
            raise KeycloakError(f"Failed to retrieve user after creation: {username}")

        logger.info("Created user: %s (%s)", username, created_user["id"])
        return created_user["id"], True

    async def create_user(
        self,
        username: str,
        *,
        email: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        temporary_password: str | None = None,
        enabled: bool = True,
        temporary: bool = True,
        email_verified: bool = False,
    ) -> None:
        """Create a Keycloak user, letting Keycloak assign the UUID.

        Prefer ensure_user() for idempotent provisioning — it checks for
        an existing user by username before creating.

        If ``temporary_password`` is provided the credential is set immediately.
        When ``temporary=True`` (default) the user is forced to change it on
        first login (requiredActions: UPDATE_PASSWORD). When ``temporary=False``
        the password is set without forcing a reset.
        """
        payload: dict[str, Any] = {
            "username": username,
            "enabled": enabled,
        }
        if email:
            payload["email"] = email
            payload["emailVerified"] = email_verified
        if first_name:
            payload["firstName"] = first_name
        if last_name:
            payload["lastName"] = last_name
        if temporary_password:
            if temporary:
                payload["requiredActions"] = ["UPDATE_PASSWORD"]
            payload["credentials"] = [
                {
                    "type": "password",
                    "value": temporary_password,
                    "temporary": temporary,
                }
            ]

        logger.debug("Creating user: %s", username)
        await self._post("/users", json=payload)

    # -------------------------------------------------------------------------
    # Groups
    # -------------------------------------------------------------------------

    async def get_group_by_path(self, path: str) -> "dict[str, Any] | None":
        """Look up a group by its path (e.g. '/viewers').

        Uses the search endpoint then filters by exact path, because Keycloak
        has no direct GET-by-path endpoint.
        """
        name = path.lstrip("/")
        results = await self._get(f"/groups?search={name}&exact=true")
        for group in results or []:
            if group.get("path") == path:
                return group
        return None

    async def create_group(self, name: str) -> str:
        """Create a top-level realm group. Returns the group ID."""
        await self._post("/groups", json={"name": name})
        group = await self.get_group_by_path(f"/{name}")
        if not group:
            raise KeycloakError(f"Failed to retrieve created group: /{name}")
        logger.info("Created group: /%s (%s)", name, group["id"])
        return group["id"]

    async def ensure_group(self, path: str) -> tuple[str, bool]:
        """Ensure a top-level realm group exists, creating it if absent.

        Only supports top-level groups (no parent). Returns (group_id, created).
        Idempotent.
        """
        existing = await self.get_group_by_path(path)
        if existing:
            logger.debug("Group '%s' already exists (%s)", path, existing["id"])
            return existing["id"], False
        name = path.lstrip("/")
        group_id = await self.create_group(name)
        return group_id, True

    async def ensure_realm_groups(self) -> bool:
        """Ensure the standard role-hierarchy groups exist at realm level.

        Creates admins, managers, editors, viewers if absent.
        Returns True if anything was created.
        """
        changed = False
        for name in ROLE_HIERARCHY:
            _, created = await self.ensure_group(f"/{name}")
            changed = changed or created
        return changed

    async def add_user_to_group(self, user_id: str, group_id: str) -> None:
        """Add a user to a group."""
        logger.debug("Adding user %s to group %s", user_id, group_id)
        await self._put(f"/users/{user_id}/groups/{group_id}")
        logger.info("Added user %s to group %s", user_id, group_id)

    async def set_user_password(
        self,
        user_id: str,
        password: str,
        temporary: bool = True,
    ) -> None:
        """Set (or reset) a user's password.

        If temporary=True the user is forced to change it on next login.
        """
        payload = {
            "type": "password",
            "value": password,
            "temporary": temporary,
        }
        logger.debug("Setting password for user %s", user_id)
        await self._put(f"/users/{user_id}/reset-password", json=payload)
        logger.info("Password set for user %s", user_id)

    async def add_user_to_group_with_retry(
        self,
        user_id: str,
        group_id: str,
        retries: int = 5,
        delay: float = 0.5,
    ) -> None:
        """Add a user to a group, retrying on 404.

        Keycloak can return 404 immediately after user creation due to
        eventual consistency — the user record is committed but not yet
        visible to all endpoints. Retrying with a small delay resolves this.

        Raises KeycloakNotFoundError if still failing after all retries.
        """
        for attempt in range(retries):
            try:
                await self.add_user_to_group(user_id, group_id)
                return
            except KeycloakNotFoundError:
                if attempt < retries - 1:
                    logger.debug(
                        "User %s not yet available for group assignment, "
                        "retrying (%d/%d)...",
                        user_id,
                        attempt + 1,
                        retries,
                    )
                    await asyncio.sleep(delay)
                else:
                    raise

    # -------------------------------------------------------------------------
    # Organizations
    # -------------------------------------------------------------------------

    async def get_realm_settings(self) -> dict[str, Any]:
        """Get the full realm representation."""
        return await self._get("")

    async def update_realm_settings(self, settings: dict[str, Any]) -> None:
        """Update the realm representation."""
        await self._put("", json=settings)

    async def ensure_organizations_enabled(self) -> bool:
        """Enable organizations on the realm if not already enabled.

        Idempotent. Returns True if organizations were just enabled.
        """
        realm = await self.get_realm_settings()
        if realm.get("organizationsEnabled"):
            logger.info("Organizations already enabled on realm")
            return False
        realm["organizationsEnabled"] = True
        await self.update_realm_settings(realm)
        logger.info("Organizations enabled on realm")
        return True

    async def list_organizations(self, max_results: int = 1000) -> list[dict[str, Any]]:
        """List all organizations in the realm."""
        return await self._get(f"/organizations?max={max_results}") or []

    async def get_organization_by_alias(self, alias: str) -> dict[str, Any] | None:
        """Get an organization by exact alias. Returns None if not found.

        KC's search param matches on name, not alias, so we list all and filter
        client-side for a reliable alias lookup.
        """
        orgs = await self.list_organizations()
        for org in orgs:
            if org.get("alias") == alias:
                return org
        return None

    async def create_organization(
        self,
        alias: str,
        name: str,
        description: str = "",
        attributes: dict[str, list[str]] | None = None,
    ) -> str:
        """Create an organization. Returns the organization ID."""
        payload: dict[str, Any] = {
            "alias": alias,
            "name": name,
            "description": description,
            "enabled": True,
            "attributes": attributes or {},
            "domains": [],
        }
        await self._post("/organizations", json=payload)
        org = await self.get_organization_by_alias(alias)
        if not org:
            raise KeycloakError(f"Failed to retrieve created organization: {alias}")
        logger.info("Created organization: %s (id=%s)", alias, org["id"])
        return org["id"]

    async def ensure_organization(
        self,
        alias: str,
        name: str,
        description: str = "",
        attributes: dict[str, list[str]] | None = None,
    ) -> tuple[str, bool]:
        """Ensure an organization exists with up-to-date attributes.

        Creates the org if it doesn't exist; updates (upserts) attributes on
        existing orgs so re-running sync always converges.

        Returns (org_id, created) where created=True if newly created.
        """
        org = await self.get_organization_by_alias(alias)
        if org:
            org_id = org["id"]
            if attributes:
                current_attrs = org.get("attributes") or {}
                if current_attrs != attributes:
                    org["attributes"] = attributes
                    await self._put(f"/organizations/{org_id}", json=org)
                    logger.info(
                        "Updated attributes on organization %s: %s", alias, attributes
                    )
                else:
                    logger.debug("Organization already exists: %s (%s)", alias, org_id)
            return org_id, False
        org_id = await self.create_organization(alias, name, description, attributes)
        return org_id, True

    async def get_organization_members(self, org_id: str) -> list[dict[str, Any]]:
        """Get all members of an organization."""
        return await self._get(f"/organizations/{org_id}/members") or []

    async def add_user_to_organization(self, org_id: str, user_id: str) -> None:
        """Add a user to an organization by Keycloak user UUID."""
        logger.debug("Adding user %s to organization %s", user_id, org_id)
        await self._post(f"/organizations/{org_id}/members", json=user_id)
        logger.info("Added user %s to organization %s", user_id, org_id)

    async def is_user_in_organization(self, org_id: str, user_id: str) -> bool:
        """Whether a user is a member of an organization, asked one user at a time.

        Deliberately not `get_organization_members`: that endpoint takes no
        `first`/`max`, so a large organization answers with whatever page
        Keycloak feels like and a member past the end reads as absent. A check
        that under-reports membership is worse than no check — it would report
        drift that is not there, and an operator who chases one false finding
        stops reading the next real one.
        """
        try:
            await self._get(f"/organizations/{org_id}/members/{user_id}")
            return True
        except KeycloakNotFoundError:
            return False

    async def get_user_groups(self, user_id: str) -> list[dict[str, Any]]:
        """The groups a user belongs to, read from the user rather than the group.

        The other direction — `GET /groups/{id}/members` — ignores `search` and
        `exact` (ADR-0004), so finding one member there is a paged scan of the
        whole group. Asking the user is one call and cannot miss.
        """
        return await self._get(f"/users/{user_id}/groups") or []

    async def ensure_user_in_organization(self, org_id: str, user_id: str) -> bool:
        """Ensure a user is a member of an organization.

        Idempotent. Returns True if the user was just added.
        Uses a direct membership check rather than listing all members to avoid
        pagination gaps on large organizations.
        """
        if await self.is_user_in_organization(org_id, user_id):
            logger.debug("User %s already in organization %s", user_id, org_id)
            return False
        try:
            await self.add_user_to_organization(org_id, user_id)
            return True
        except KeycloakConflictError:
            # Race condition: another process added the user between the check and add
            logger.debug(
                "User %s already in organization %s (conflict)", user_id, org_id
            )
            return False

    async def list_org_roles(self, org_id: str) -> list[dict[str, Any]]:
        """List roles defined on an organization.

        Returns an empty list on 404 — KC 26 does not expose this endpoint;
        custom org roles require KC 27+.
        """
        try:
            return await self._get(f"/organizations/{org_id}/roles") or []
        except KeycloakNotFoundError:
            return []

    async def ensure_org_role(
        self, org_id: str, role_name: str
    ) -> dict[str, Any] | None:
        """Ensure a role exists on an organization, creating it if necessary.

        Returns the role representation, or None if the KC version does not support
        custom org role creation (POST returns 405 — available from KC 27+).
        Idempotent.
        """
        roles = await self.list_org_roles(org_id)
        existing = next((r for r in roles if r.get("name") == role_name), None)
        if existing:
            logger.debug("Org role '%s' already exists on %s", role_name, org_id)
            return existing
        try:
            await self._post(f"/organizations/{org_id}/roles", json={"name": role_name})
        except KeycloakError as e:
            if getattr(e, "status_code", None) in (404, 405):
                logger.debug(
                    "Org role creation not supported (HTTP %s) — skipping",
                    e.status_code,
                )
                return None
            raise
        roles = await self.list_org_roles(org_id)
        role = next((r for r in roles if r.get("name") == role_name), None)
        if not role:
            raise KeycloakError(
                f"Created org role '{role_name}' but could not retrieve it from {org_id}"
            )
        logger.info("Created org role '%s' on organization %s", role_name, org_id)
        return role

    async def get_member_org_roles(
        self, org_id: str, user_id: str
    ) -> list[dict[str, Any]]:
        """Get org roles assigned to a specific member.

        Returns an empty list on 404 — KC 26 does not expose this endpoint.
        """
        try:
            return (
                await self._get(f"/organizations/{org_id}/members/{user_id}/roles")
                or []
            )
        except KeycloakNotFoundError:
            return []

    async def assign_org_role_to_member(
        self, org_id: str, user_id: str, role: dict[str, Any]
    ) -> None:
        """Assign an org role to a member."""
        logger.debug(
            "Assigning org role '%s' to user %s in org %s",
            role.get("name"),
            user_id,
            org_id,
        )
        await self._post(
            f"/organizations/{org_id}/members/{user_id}/roles", json=[role]
        )
        logger.info("Assigned org role '%s' to user %s", role.get("name"), user_id)

    async def ensure_member_org_role(
        self, org_id: str, user_id: str, role_name: str
    ) -> bool:
        """Ensure a member has a specific org role, assigning it if missing.

        Idempotent. Returns True if the role was just assigned.
        Returns False if the role does not exist on the org (e.g. KC version does
        not support custom org roles — see ensure_org_role).
        """
        current = await self.get_member_org_roles(org_id, user_id)
        if any(r.get("name") == role_name for r in current):
            logger.debug("User %s already has org role '%s'", user_id, role_name)
            return False
        roles = await self.list_org_roles(org_id)
        role = next((r for r in roles if r.get("name") == role_name), None)
        if not role:
            logger.debug(
                "Org role '%s' not present on organization %s — skipping member assignment",
                role_name,
                org_id,
            )
            return False
        await self.assign_org_role_to_member(org_id, user_id, role)
        return True

    # -------------------------------------------------------------------------
    # Organization Groups
    # -------------------------------------------------------------------------

    async def list_org_groups(self, org_id: str) -> list[dict[str, Any]]:
        """List groups defined on an organization."""
        try:
            return await self._get(f"/organizations/{org_id}/groups") or []
        except KeycloakNotFoundError:
            return []

    async def get_org_group_by_name(
        self, org_id: str, name: str
    ) -> dict[str, Any] | None:
        """Find an organization group by name. Returns None if not found."""
        groups = await self.list_org_groups(org_id)
        return next((g for g in groups if g.get("name") == name), None)

    async def ensure_org_group(self, org_id: str, name: str) -> tuple[str, bool]:
        """Ensure an organization group exists, creating it if absent.

        Returns (group_id, created). Idempotent.
        """
        existing = await self.get_org_group_by_name(org_id, name)
        if existing:
            logger.debug("Org group '%s' already exists on %s (%s)", name, org_id, existing["id"])
            return existing["id"], False
        await self._post(f"/organizations/{org_id}/groups", json={"name": name})
        group = await self.get_org_group_by_name(org_id, name)
        if not group:
            raise KeycloakError(f"Failed to retrieve created org group '{name}' on {org_id}")
        logger.info("Created org group '%s' on organization %s (%s)", name, org_id, group["id"])
        return group["id"], True

    async def ensure_user_in_org_group(
        self, org_id: str, group_id: str, user_id: str
    ) -> bool:
        """Ensure a user is a member of an organization group.

        Returns True if the user was just added. Idempotent.
        """
        try:
            await self._get(
                f"/organizations/{org_id}/groups/{group_id}/members/{user_id}"
            )
            logger.debug(
                "User %s already in org group %s/%s", user_id, org_id, group_id
            )
            return False
        except KeycloakNotFoundError:
            pass
        try:
            await self._put(
                f"/organizations/{org_id}/groups/{group_id}/members/{user_id}"
            )
            logger.info(
                "Added user %s to org group %s/%s", user_id, org_id, group_id
            )
            return True
        except KeycloakConflictError:
            return False
