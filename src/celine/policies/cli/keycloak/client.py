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

    async def _put(self, path: str, json: dict | None = None) -> Any:
        """Make PUT request to admin API."""
        url = f"{self._settings.admin_url}{path}"
        headers = await self._headers()
        response = await self._client.put(url, headers=headers, json=json)
        return self._handle_response(response, expected_status=[200, 204])

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

    async def assign_realm_management_roles(self, client_uuid: str) -> None:
        """Ensure the service account has all required realm-management roles.

        Idempotent: fetches currently assigned roles first and only assigns
        what is missing. Raises if any required role is missing or cannot be
        verified after assignment.
        """
        sa_user = await self.get_service_account_user(client_uuid)
        user_id = sa_user["id"]

        rm_client = await self.get_realm_management_client()
        if not rm_client:
            raise KeycloakError("realm-management client not found")
        rm_client_uuid = rm_client["id"]

        all_roles = await self.get_client_roles(rm_client_uuid)
        role_map = {r["name"]: r for r in all_roles}

        for role_name in self.REQUIRED_REALM_MGMT_ROLES:
            if role_name not in role_map:
                raise KeycloakError(
                    f"Required role '{role_name}' not found in realm-management. "
                    f"Available: {sorted(role_map.keys())}"
                )

        current_roles = await self.get_user_client_roles(user_id, rm_client_uuid)
        current_role_names = {r["name"] for r in current_roles}

        missing_roles = [
            role_map[name]
            for name in self.REQUIRED_REALM_MGMT_ROLES
            if name not in current_role_names
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
        still_missing = [
            name
            for name in self.REQUIRED_REALM_MGMT_ROLES
            if name not in assigned_names
        ]
        if still_missing:
            raise KeycloakError(
                f"Role assignment failed — still missing after assign: {still_missing}"
            )

        logger.info(
            "Successfully assigned realm-management roles: %s",
            [r["name"] for r in missing_roles],
        )

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
                and client_id
                not in {
                    "admin-cli",
                    "broker",
                    "realm-management",
                    "security-admin-console",
                }
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

    async def list_organizations(
        self, search: str | None = None, exact: bool = False
    ) -> list[dict[str, Any]]:
        """List organizations, optionally filtered by search query."""
        path = "/organizations"
        params: list[str] = []
        if search:
            params.append(f"search={search}")
        if exact:
            params.append("exact=true")
        if params:
            path += "?" + "&".join(params)
        return await self._get(path) or []

    async def get_organization_by_alias(self, alias: str) -> dict[str, Any] | None:
        """Get an organization by exact alias. Returns None if not found."""
        orgs = await self.list_organizations(search=alias, exact=True)
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
        """Ensure an organization exists, creating it if necessary.

        Returns (org_id, created) where created=True if newly created.
        Idempotent.
        """
        org = await self.get_organization_by_alias(alias)
        if org:
            logger.debug("Organization already exists: %s (%s)", alias, org["id"])
            return org["id"], False
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

    async def ensure_user_in_organization(self, org_id: str, user_id: str) -> bool:
        """Ensure a user is a member of an organization.

        Idempotent. Returns True if the user was just added.
        """
        members = await self.get_organization_members(org_id)
        if any(m.get("id") == user_id for m in members):
            logger.debug("User %s already in organization %s", user_id, org_id)
            return False
        await self.add_user_to_organization(org_id, user_id)
        return True
