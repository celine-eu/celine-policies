"""Keycloak Admin API client.

Wraps the Keycloak Admin REST API for managing:
- Client scopes
- Clients
- Scope-to-client assignments
- Service account roles
- Protocol mappers (audience mappers for cross-service calls)
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

    scopes: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )  # name -> scope data
    clients: dict[str, dict[str, Any]] = field(
        default_factory=dict
    )  # client_id -> client data
    client_default_scopes: dict[str, set[str]] = field(
        default_factory=dict
    )  # client_id -> scope names
    client_optional_scopes: dict[str, set[str]] = field(
        default_factory=dict
    )  # client_id -> scope names

    # Audience mappers currently on each client.
    # Maps client_id -> set of audience values (target client_ids).
    # Only includes mappers whose name starts with AUDIENCE_MAPPER_PREFIX,
    # so manually created mappers are never touched.
    client_audience_mappers: dict[str, dict[str, str]] = field(
        default_factory=dict
    )  # client_id -> {audience_client_id -> mapper_id}


class KeycloakAdminClient:
    """Async client for Keycloak Admin REST API."""

    # Well-known Keycloak built-in scopes to ignore
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
        "basic",  # Added in newer Keycloak
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
        # Admin users authenticate against the master realm
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

    async def _post(self, path: str, json: list | dict | None = None) -> Any:
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
        """Create a new client scope.

        Returns the scope ID.
        """
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

        # Fetch the created scope to get its ID
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
            # Client credentials flow settings
            "publicClient": False,
            "serviceAccountsEnabled": service_account_enabled,
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            # Authentication
            "clientAuthenticatorType": "client-secret",
        }

        if secret:
            payload["secret"] = secret

        logger.debug("Creating client: %s", client_id)
        await self._post("/clients", json=payload)

        # Fetch the created client
        client = await self.get_client_by_client_id(client_id)
        if not client:
            raise KeycloakError(f"Failed to retrieve created client: {client_id}")

        client_uuid = client["id"]

        # Get or generate secret
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
    ) -> None:
        """Update an existing client."""
        # Get current client to preserve settings
        current = await self.get_client(client_uuid)

        payload = {
            **current,
            "clientId": client_id,
            "name": name or client_id,
            "description": description,
            "serviceAccountsEnabled": service_account_enabled,
            # Ensure client credentials settings
            "publicClient": False,
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
        }

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

        Args:
            client_uuid: UUID of the client to add the mapper to.
            audience_client_id: The client_id value to embed as audience
                                 (e.g. 'svc-dataset-api').

        Returns:
            The mapper ID.
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

        # Keycloak returns the created mapper with its ID on 201
        if result and isinstance(result, dict):
            mapper_id = result.get("id", "")
        else:
            # Fall back: re-fetch to get the ID
            mappers = await self.get_client_protocol_mappers(client_uuid)
            mapper_id = next(
                (m["id"] for m in mappers if m.get("name") == mapper_name), ""
            )

        logger.info(
            "Created audience mapper '%s' on client %s (id=%s)",
            mapper_name, client_uuid, mapper_id,
        )
        return mapper_id

    async def delete_protocol_mapper(
        self, client_uuid: str, mapper_id: str
    ) -> None:
        """Delete a protocol mapper from a client."""
        logger.debug("Deleting protocol mapper %s from client %s", mapper_id, client_uuid)
        await self._delete(
            f"/clients/{client_uuid}/protocol-mappers/models/{mapper_id}"
        )
        logger.info("Deleted protocol mapper %s from client %s", mapper_id, client_uuid)

    # -------------------------------------------------------------------------
    # Service Account Roles (for bootstrap)
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

    async def assign_realm_management_roles(self, client_uuid: str) -> None:
        """Assign realm-management roles to a client's service account.

        Grants:
        - manage-clients
        - manage-realm (for client scopes)
        - view-clients
        - view-realm
        """
        # Get the service account user
        sa_user = await self.get_service_account_user(client_uuid)
        user_id = sa_user["id"]

        # Get realm-management client
        rm_client = await self.get_realm_management_client()
        if not rm_client:
            raise KeycloakError("realm-management client not found")

        rm_client_uuid = rm_client["id"]

        # Get available roles
        all_roles = await self.get_client_roles(rm_client_uuid)
        role_map = {r["name"]: r for r in all_roles}

        # Roles we need
        needed_roles = ["manage-clients", "manage-realm", "view-clients", "view-realm"]
        roles_to_assign = []

        for role_name in needed_roles:
            if role_name in role_map:
                roles_to_assign.append(role_map[role_name])
            else:
                logger.warning("Role not found: %s", role_name)

        if roles_to_assign:
            await self.assign_client_roles_to_user(
                user_id, rm_client_uuid, roles_to_assign
            )
            logger.info(
                "Assigned realm-management roles to service account: %s",
                [r["name"] for r in roles_to_assign],
            )

    # -------------------------------------------------------------------------
    # State Fetching
    # -------------------------------------------------------------------------

    async def fetch_current_state(self) -> CurrentState:
        """Fetch the current state of all relevant resources."""
        state = CurrentState()

        # Fetch all scopes
        scopes = await self.list_client_scopes()
        for scope in scopes:
            name = scope.get("name", "")
            if name and name not in self.BUILTIN_SCOPES:
                state.scopes[name] = scope

        # Fetch all clients
        clients = await self.list_clients()
        for client in clients:
            client_id = client.get("clientId", "")
            # Skip Keycloak internal clients
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

                # Fetch scope assignments
                default_scopes = await self.get_client_default_scopes(client_uuid)
                state.client_default_scopes[client_id] = {
                    s["name"] for s in default_scopes if s.get("name")
                }

                optional_scopes = await self.get_client_optional_scopes(client_uuid)
                state.client_optional_scopes[client_id] = {
                    s["name"] for s in optional_scopes if s.get("name")
                }

                # Fetch audience mappers managed by this CLI
                mappers = await self.get_client_protocol_mappers(client_uuid)
                state.client_audience_mappers[client_id] = {
                    m["config"]["included.client.audience"]: m["id"]
                    for m in mappers
                    if m.get("name", "").startswith(AUDIENCE_MAPPER_PREFIX)
                    and m.get("protocolMapper") == "oidc-audience-mapper"
                    and m.get("config", {}).get("included.client.audience")
                }

        return state