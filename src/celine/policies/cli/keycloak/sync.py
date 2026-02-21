"""Sync logic for Keycloak resources.

Computes a diff between desired state (YAML) and current state (Keycloak),
then applies changes to converge to the desired state.

Audience mapper logic
---------------------
Each client with a `scopes_prefix` declared owns a family of scopes.
When a client references a scope whose prefix belongs to a *different* client,
the CLI automatically manages a hardcoded audience mapper on the requesting
client, so the owning service will accept its tokens.

Mappers are named with the AUDIENCE_MAPPER_PREFIX sentinel so we never touch
mappers created manually outside this tool.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from celine.policies.cli.keycloak.client import (
    AUDIENCE_MAPPER_PREFIX,
    CurrentState,
    KeycloakAdminClient,
    KeycloakConflictError,
    KeycloakNotFoundError,
)
from celine.policies.cli.keycloak.models import ClientConfig, KeycloakConfig, ScopeConfig

logger = logging.getLogger(__name__)


@dataclass
class ScopeAction:
    """Action to perform on a scope."""
    scope: ScopeConfig
    action: str  # "create", "update"
    current: dict[str, Any] | None = None


@dataclass
class ClientAction:
    """Action to perform on a client."""
    client: ClientConfig
    action: str  # "create", "update"
    current: dict[str, Any] | None = None


@dataclass
class ScopeAssignmentAction:
    """Action to perform on a scope assignment."""
    client_id: str
    scope_name: str
    assignment_type: str  # "default", "optional"
    action: str  # "add", "remove"


@dataclass
class AudienceMapperAction:
    """Action to add or remove a hardcoded audience mapper on a client.

    Attributes:
        client_id:          The requesting client (the one getting the mapper).
        audience_client_id: The target service client_id to embed as audience.
        action:             "add" or "remove".
        mapper_id:          Keycloak mapper UUID — only set for "remove" actions.
    """
    client_id: str
    audience_client_id: str
    action: str  # "add", "remove"
    mapper_id: str | None = None  # populated for "remove" only


@dataclass
class SyncPlan:
    """Plan of actions to sync Keycloak to desired state."""

    # Scope actions
    scopes_to_create: list[ScopeAction] = field(default_factory=list)
    scopes_to_update: list[ScopeAction] = field(default_factory=list)

    # Client actions
    clients_to_create: list[ClientAction] = field(default_factory=list)
    clients_to_update: list[ClientAction] = field(default_factory=list)

    # Scope assignment actions
    scope_assignments_to_add: list[ScopeAssignmentAction] = field(default_factory=list)
    scope_assignments_to_remove: list[ScopeAssignmentAction] = field(default_factory=list)

    # Audience mapper actions
    audience_mappers_to_add: list[AudienceMapperAction] = field(default_factory=list)
    audience_mappers_to_remove: list[AudienceMapperAction] = field(default_factory=list)

    # Orphans (exist in Keycloak but not in config)
    orphan_scopes: list[str] = field(default_factory=list)
    orphan_clients: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """Check if there are any changes to apply."""
        return bool(
            self.scopes_to_create
            or self.scopes_to_update
            or self.clients_to_create
            or self.clients_to_update
            or self.scope_assignments_to_add
            or self.scope_assignments_to_remove
            or self.audience_mappers_to_add
            or self.audience_mappers_to_remove
        )

    @property
    def has_orphans(self) -> bool:
        """Check if there are orphaned resources."""
        return bool(self.orphan_scopes or self.orphan_clients)

    def summary(self) -> str:
        """Get a human-readable summary of the plan."""
        lines = []

        if self.scopes_to_create:
            lines.append(f"Scopes to create: {len(self.scopes_to_create)}")
            for action in self.scopes_to_create:
                lines.append(f"  + {action.scope.name}")

        if self.scopes_to_update:
            lines.append(f"Scopes to update: {len(self.scopes_to_update)}")
            for action in self.scopes_to_update:
                lines.append(f"  ~ {action.scope.name}")

        if self.clients_to_create:
            lines.append(f"Clients to create: {len(self.clients_to_create)}")
            for action in self.clients_to_create:
                lines.append(f"  + {action.client.client_id}")

        if self.clients_to_update:
            lines.append(f"Clients to update: {len(self.clients_to_update)}")
            for action in self.clients_to_update:
                lines.append(f"  ~ {action.client.client_id}")

        if self.scope_assignments_to_add:
            lines.append(f"Scope assignments to add: {len(self.scope_assignments_to_add)}")
            for action in self.scope_assignments_to_add:
                lines.append(f"  + {action.client_id} <- {action.scope_name} ({action.assignment_type})")

        if self.scope_assignments_to_remove:
            lines.append(f"Scope assignments to remove: {len(self.scope_assignments_to_remove)}")
            for action in self.scope_assignments_to_remove:
                lines.append(f"  - {action.client_id} <- {action.scope_name} ({action.assignment_type})")

        if self.audience_mappers_to_add:
            lines.append(f"Audience mappers to add: {len(self.audience_mappers_to_add)}")
            for action in self.audience_mappers_to_add:
                lines.append(f"  + {action.client_id} -> aud:{action.audience_client_id}")

        if self.audience_mappers_to_remove:
            lines.append(f"Audience mappers to remove: {len(self.audience_mappers_to_remove)}")
            for action in self.audience_mappers_to_remove:
                lines.append(f"  - {action.client_id} -> aud:{action.audience_client_id}")

        if self.orphan_scopes:
            lines.append(f"Orphan scopes (use --prune to delete): {len(self.orphan_scopes)}")
            for name in self.orphan_scopes:
                lines.append(f"  ? {name}")

        if self.orphan_clients:
            lines.append(f"Orphan clients (use --prune to delete): {len(self.orphan_clients)}")
            for client_id in self.orphan_clients:
                lines.append(f"  ? {client_id}")

        if not lines:
            lines.append("No changes needed - Keycloak is in sync")

        return "\n".join(lines)


@dataclass
class SyncResult:
    """Result of applying a sync plan."""

    scopes_created: list[str] = field(default_factory=list)
    scopes_updated: list[str] = field(default_factory=list)
    scopes_deleted: list[str] = field(default_factory=list)

    clients_created: list[str] = field(default_factory=list)
    clients_updated: list[str] = field(default_factory=list)
    clients_deleted: list[str] = field(default_factory=list)

    scope_assignments_added: list[tuple[str, str, str]] = field(default_factory=list)
    scope_assignments_removed: list[tuple[str, str, str]] = field(default_factory=list)

    audience_mappers_added: list[tuple[str, str]] = field(default_factory=list)   # (client_id, audience)
    audience_mappers_removed: list[tuple[str, str]] = field(default_factory=list)  # (client_id, audience)

    # Client secrets (client_id -> secret)
    client_secrets: dict[str, str] = field(default_factory=dict)

    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Check if sync completed without errors."""
        return len(self.errors) == 0

    def summary(self) -> str:
        """Get a human-readable summary of the result."""
        lines = []

        if self.scopes_created:
            lines.append(f"Created {len(self.scopes_created)} scopes: {', '.join(self.scopes_created)}")
        if self.scopes_updated:
            lines.append(f"Updated {len(self.scopes_updated)} scopes: {', '.join(self.scopes_updated)}")
        if self.scopes_deleted:
            lines.append(f"Deleted {len(self.scopes_deleted)} scopes: {', '.join(self.scopes_deleted)}")

        if self.clients_created:
            lines.append(f"Created {len(self.clients_created)} clients: {', '.join(self.clients_created)}")
        if self.clients_updated:
            lines.append(f"Updated {len(self.clients_updated)} clients: {', '.join(self.clients_updated)}")
        if self.clients_deleted:
            lines.append(f"Deleted {len(self.clients_deleted)} clients: {', '.join(self.clients_deleted)}")

        if self.scope_assignments_added:
            lines.append(f"Added {len(self.scope_assignments_added)} scope assignments")
        if self.scope_assignments_removed:
            lines.append(f"Removed {len(self.scope_assignments_removed)} scope assignments")

        if self.audience_mappers_added:
            lines.append(f"Added {len(self.audience_mappers_added)} audience mappers")
            for client_id, aud in self.audience_mappers_added:
                lines.append(f"  + {client_id} -> aud:{aud}")
        if self.audience_mappers_removed:
            lines.append(f"Removed {len(self.audience_mappers_removed)} audience mappers")
            for client_id, aud in self.audience_mappers_removed:
                lines.append(f"  - {client_id} -> aud:{aud}")

        if self.errors:
            lines.append(f"Errors: {len(self.errors)}")
            for err in self.errors:
                lines.append(f"  ! {err}")

        if not lines:
            lines.append("No changes applied")

        return "\n".join(lines)


def compute_sync_plan(
    config: KeycloakConfig,
    current: CurrentState,
    managed_prefix: str | None = None,
) -> SyncPlan:
    """Compute the sync plan by diffing desired config against current state.

    Args:
        config: Desired configuration from YAML
        current: Current state from Keycloak
        managed_prefix: If set, only manage resources with this prefix (for orphan detection)

    Returns:
        SyncPlan describing all changes needed
    """
    plan = SyncPlan()

    # Build lookup sets
    desired_scope_names = config.get_scope_names()
    desired_client_ids = config.get_client_ids()
    current_scope_names = set(current.scopes.keys())
    current_client_ids = set(current.clients.keys())

    # prefix -> owning client_id, e.g. {"dataset": "svc-dataset-api", ...}
    prefix_to_client = config.build_prefix_to_client_map()

    # -------------------------------------------------------------------------
    # Scopes
    # -------------------------------------------------------------------------

    for scope_config in config.scopes:
        if scope_config.name in current_scope_names:
            current_scope = current.scopes[scope_config.name]
            if _scope_needs_update(scope_config, current_scope):
                plan.scopes_to_update.append(ScopeAction(
                    scope=scope_config,
                    action="update",
                    current=current_scope,
                ))
        else:
            plan.scopes_to_create.append(ScopeAction(
                scope=scope_config,
                action="create",
            ))

    # Find orphan scopes
    for scope_name in current_scope_names:
        if scope_name not in desired_scope_names:
            if managed_prefix is None or scope_name.startswith(managed_prefix):
                plan.orphan_scopes.append(scope_name)

    # -------------------------------------------------------------------------
    # Clients
    # -------------------------------------------------------------------------

    for client_config in config.clients:
        if client_config.client_id in current_client_ids:
            current_client = current.clients[client_config.client_id]
            if _client_needs_update(client_config, current_client):
                plan.clients_to_update.append(ClientAction(
                    client=client_config,
                    action="update",
                    current=current_client,
                ))
        else:
            plan.clients_to_create.append(ClientAction(
                client=client_config,
                action="create",
            ))

    # Find orphan clients
    for client_id in current_client_ids:
        if client_id not in desired_client_ids:
            if managed_prefix is None or client_id.startswith(managed_prefix):
                if client_id != "celine-admin-cli":
                    plan.orphan_clients.append(client_id)

    # -------------------------------------------------------------------------
    # Scope Assignments
    # -------------------------------------------------------------------------

    for client_config in config.clients:
        client_id = client_config.client_id

        current_default = current.client_default_scopes.get(client_id, set())
        current_optional = current.client_optional_scopes.get(client_id, set())

        desired_default = set(client_config.default_scopes)
        desired_optional = set(client_config.optional_scopes)

        # Default scope changes
        for scope_name in desired_default - current_default:
            if scope_name in current_optional:
                plan.scope_assignments_to_remove.append(ScopeAssignmentAction(
                    client_id=client_id,
                    scope_name=scope_name,
                    assignment_type="optional",
                    action="remove",
                ))
            plan.scope_assignments_to_add.append(ScopeAssignmentAction(
                client_id=client_id,
                scope_name=scope_name,
                assignment_type="default",
                action="add",
            ))

        # Optional scope changes
        for scope_name in desired_optional - current_optional:
            if scope_name in current_default:
                plan.scope_assignments_to_remove.append(ScopeAssignmentAction(
                    client_id=client_id,
                    scope_name=scope_name,
                    assignment_type="default",
                    action="remove",
                ))
            plan.scope_assignments_to_add.append(ScopeAssignmentAction(
                client_id=client_id,
                scope_name=scope_name,
                assignment_type="optional",
                action="add",
            ))

        # Scopes to remove (in current but not in desired)
        all_desired = desired_default | desired_optional

        for scope_name in current_default - all_desired:
            if scope_name not in KeycloakAdminClient.BUILTIN_SCOPES:
                plan.scope_assignments_to_remove.append(ScopeAssignmentAction(
                    client_id=client_id,
                    scope_name=scope_name,
                    assignment_type="default",
                    action="remove",
                ))

        for scope_name in current_optional - all_desired:
            if scope_name not in KeycloakAdminClient.BUILTIN_SCOPES:
                plan.scope_assignments_to_remove.append(ScopeAssignmentAction(
                    client_id=client_id,
                    scope_name=scope_name,
                    assignment_type="optional",
                    action="remove",
                ))

    # -------------------------------------------------------------------------
    # Audience Mappers
    # -------------------------------------------------------------------------
    # For every client with a scopes_prefix, compute which foreign service
    # audiences its tokens need, then diff against current mappers.

    for client_config in config.clients:
        if client_config.scopes_prefix is None:
            # Exempt clients (celine-cli, mqtt-only, etc.)
            continue

        client_id = client_config.client_id

        # Desired audiences: one per foreign scope prefix that resolves to a
        # known owning client.
        desired_audiences: set[str] = set()
        for prefix in client_config.foreign_scope_prefixes():
            owning_client = prefix_to_client.get(prefix)
            if owning_client:
                desired_audiences.add(owning_client)
            else:
                logger.warning(
                    "Client %s references scope prefix '%s' but no client owns it — "
                    "skipping audience mapper",
                    client_id, prefix,
                )

        # Current audiences: mappers already on this client
        current_audience_map = current.client_audience_mappers.get(client_id, {})
        current_audiences = set(current_audience_map.keys())

        # Add missing mappers
        for audience in desired_audiences - current_audiences:
            plan.audience_mappers_to_add.append(AudienceMapperAction(
                client_id=client_id,
                audience_client_id=audience,
                action="add",
            ))

        # Remove stale mappers (audience no longer needed)
        for audience in current_audiences - desired_audiences:
            plan.audience_mappers_to_remove.append(AudienceMapperAction(
                client_id=client_id,
                audience_client_id=audience,
                action="remove",
                mapper_id=current_audience_map[audience],
            ))

    return plan


def _scope_needs_update(config: ScopeConfig, current: dict[str, Any]) -> bool:
    """Check if a scope needs to be updated."""
    if config.description != current.get("description", ""):
        return True

    attrs = current.get("attributes", {})
    include_in_token = attrs.get("include.in.token.scope", "true").lower() == "true"
    if config.include_in_token_scope != include_in_token:
        return True

    return False


def _client_needs_update(config: ClientConfig, current: dict[str, Any]) -> bool:
    """Check if a client needs to be updated."""
    if config.name and config.name != current.get("name", ""):
        return True
    if config.description != current.get("description", ""):
        return True
    if config.service_account_enabled != current.get("serviceAccountsEnabled", False):
        return True

    return False


async def apply_sync_plan(
    client: KeycloakAdminClient,
    plan: SyncPlan,
    config: KeycloakConfig,
    current: CurrentState,
    prune: bool = False,
    dry_run: bool = False,
) -> SyncResult:
    """Apply a sync plan to Keycloak.

    Args:
        client: Keycloak admin client
        plan: Computed sync plan
        config: Desired configuration
        current: Current state (for lookups)
        prune: If True, delete orphaned resources
        dry_run: If True, don't actually make changes

    Returns:
        SyncResult with details of what was done
    """
    result = SyncResult()

    # Scope name -> ID
    scope_ids: dict[str, str] = {
        name: data["id"] for name, data in current.scopes.items()
    }

    # client_id -> UUID
    client_uuids: dict[str, str] = {
        client_id: data["id"] for client_id, data in current.clients.items()
    }

    # -------------------------------------------------------------------------
    # 1. Create scopes first (clients may reference them)
    # -------------------------------------------------------------------------

    for action in plan.scopes_to_create:
        scope = action.scope
        if dry_run:
            logger.info("[DRY RUN] Would create scope: %s", scope.name)
            result.scopes_created.append(scope.name)
            continue

        try:
            scope_id = await client.create_client_scope(
                name=scope.name,
                description=scope.description,
                protocol=scope.protocol,
                include_in_token_scope=scope.include_in_token_scope,
            )
            scope_ids[scope.name] = scope_id
            result.scopes_created.append(scope.name)
        except KeycloakConflictError:
            logger.warning("Scope already exists (race condition?): %s", scope.name)
            existing = await client.get_client_scope_by_name(scope.name)
            if existing:
                scope_ids[scope.name] = existing["id"]
        except Exception as e:
            result.errors.append(f"Failed to create scope {scope.name}: {e}")

    # -------------------------------------------------------------------------
    # 2. Update existing scopes
    # -------------------------------------------------------------------------

    for action in plan.scopes_to_update:
        scope = action.scope
        scope_id = scope_ids.get(scope.name) or action.current["id"]

        if dry_run:
            logger.info("[DRY RUN] Would update scope: %s", scope.name)
            result.scopes_updated.append(scope.name)
            continue

        try:
            await client.update_client_scope(
                scope_id=scope_id,
                name=scope.name,
                description=scope.description,
                protocol=scope.protocol,
                include_in_token_scope=scope.include_in_token_scope,
            )
            result.scopes_updated.append(scope.name)
        except Exception as e:
            result.errors.append(f"Failed to update scope {scope.name}: {e}")

    # -------------------------------------------------------------------------
    # 3. Create clients
    # -------------------------------------------------------------------------

    for action in plan.clients_to_create:
        client_config = action.client

        if dry_run:
            logger.info("[DRY RUN] Would create client: %s", client_config.client_id)
            result.clients_created.append(client_config.client_id)
            continue

        try:
            client_uuid, secret = await client.create_client(
                client_id=client_config.client_id,
                name=client_config.name,
                description=client_config.description,
                secret=client_config.secret,
                service_account_enabled=client_config.service_account_enabled,
            )
            client_uuids[client_config.client_id] = client_uuid
            result.clients_created.append(client_config.client_id)
            result.client_secrets[client_config.client_id] = secret
        except KeycloakConflictError:
            logger.warning("Client already exists (race condition?): %s", client_config.client_id)
            existing = await client.get_client_by_client_id(client_config.client_id)
            if existing:
                client_uuids[client_config.client_id] = existing["id"]
                secret = await client.get_client_secret(existing["id"])
                result.client_secrets[client_config.client_id] = secret
        except Exception as e:
            result.errors.append(f"Failed to create client {client_config.client_id}: {e}")

    # -------------------------------------------------------------------------
    # 4. Update existing clients
    # -------------------------------------------------------------------------

    for action in plan.clients_to_update:
        client_config = action.client
        client_uuid = client_uuids.get(client_config.client_id) or action.current["id"]

        if dry_run:
            logger.info("[DRY RUN] Would update client: %s", client_config.client_id)
            result.clients_updated.append(client_config.client_id)
            continue

        try:
            await client.update_client(
                client_uuid=client_uuid,
                client_id=client_config.client_id,
                name=client_config.name,
                description=client_config.description,
                service_account_enabled=client_config.service_account_enabled,
            )
            result.clients_updated.append(client_config.client_id)

            secret = await client.get_client_secret(client_uuid)
            result.client_secrets[client_config.client_id] = secret
        except Exception as e:
            result.errors.append(f"Failed to update client {client_config.client_id}: {e}")

    # -------------------------------------------------------------------------
    # 5. Remove scope assignments (before adding new ones to handle type changes)
    # -------------------------------------------------------------------------

    for action in plan.scope_assignments_to_remove:
        client_uuid = client_uuids.get(action.client_id)
        scope_id = scope_ids.get(action.scope_name)

        if not client_uuid:
            logger.warning("Client not found for scope removal: %s", action.client_id)
            continue

        if not scope_id:
            all_scopes = await client.list_client_scopes()
            for s in all_scopes:
                if s.get("name") == action.scope_name:
                    scope_id = s["id"]
                    break

        if not scope_id:
            logger.warning("Scope not found for removal: %s", action.scope_name)
            continue

        if dry_run:
            logger.info(
                "[DRY RUN] Would remove %s scope %s from %s",
                action.assignment_type, action.scope_name, action.client_id
            )
            result.scope_assignments_removed.append(
                (action.client_id, action.scope_name, action.assignment_type)
            )
            continue

        try:
            if action.assignment_type == "default":
                await client.remove_client_default_scope(client_uuid, scope_id)
            else:
                await client.remove_client_optional_scope(client_uuid, scope_id)

            result.scope_assignments_removed.append(
                (action.client_id, action.scope_name, action.assignment_type)
            )
        except KeycloakNotFoundError:
            pass
        except Exception as e:
            result.errors.append(
                f"Failed to remove {action.assignment_type} scope {action.scope_name} "
                f"from {action.client_id}: {e}"
            )

    # -------------------------------------------------------------------------
    # 6. Add scope assignments
    # -------------------------------------------------------------------------

    # Refresh scope_ids to include any builtin scopes we might need
    all_scopes = await client.list_client_scopes()
    for s in all_scopes:
        name = s.get("name")
        if name and name not in scope_ids:
            scope_ids[name] = s["id"]

    for action in plan.scope_assignments_to_add:
        client_uuid = client_uuids.get(action.client_id)
        scope_id = scope_ids.get(action.scope_name)

        if not client_uuid:
            logger.warning("Client not found for scope assignment: %s", action.client_id)
            continue

        if not scope_id:
            logger.warning("Scope not found for assignment: %s", action.scope_name)
            result.errors.append(f"Scope not found: {action.scope_name}")
            continue

        if dry_run:
            logger.info(
                "[DRY RUN] Would add %s scope %s to %s",
                action.assignment_type, action.scope_name, action.client_id
            )
            result.scope_assignments_added.append(
                (action.client_id, action.scope_name, action.assignment_type)
            )
            continue

        try:
            if action.assignment_type == "default":
                await client.add_client_default_scope(client_uuid, scope_id)
            else:
                await client.add_client_optional_scope(client_uuid, scope_id)

            result.scope_assignments_added.append(
                (action.client_id, action.scope_name, action.assignment_type)
            )
        except Exception as e:
            result.errors.append(
                f"Failed to add {action.assignment_type} scope {action.scope_name} "
                f"to {action.client_id}: {e}"
            )

    # -------------------------------------------------------------------------
    # 7. Add audience mappers
    # -------------------------------------------------------------------------

    for action in plan.audience_mappers_to_add:
        client_uuid = client_uuids.get(action.client_id)

        if not client_uuid:
            logger.warning("Client not found for audience mapper: %s", action.client_id)
            continue

        if dry_run:
            logger.info(
                "[DRY RUN] Would add audience mapper %s -> aud:%s",
                action.client_id, action.audience_client_id,
            )
            result.audience_mappers_added.append(
                (action.client_id, action.audience_client_id)
            )
            continue

        try:
            await client.create_audience_mapper(
                client_uuid=client_uuid,
                audience_client_id=action.audience_client_id,
            )
            result.audience_mappers_added.append(
                (action.client_id, action.audience_client_id)
            )
        except Exception as e:
            result.errors.append(
                f"Failed to add audience mapper {action.audience_client_id} "
                f"to {action.client_id}: {e}"
            )

    # -------------------------------------------------------------------------
    # 8. Remove stale audience mappers
    # -------------------------------------------------------------------------

    for action in plan.audience_mappers_to_remove:
        client_uuid = client_uuids.get(action.client_id)

        if not client_uuid:
            logger.warning("Client not found for audience mapper removal: %s", action.client_id)
            continue

        if not action.mapper_id:
            logger.warning(
                "No mapper_id for removal of aud:%s on %s — skipping",
                action.audience_client_id, action.client_id,
            )
            continue

        if dry_run:
            logger.info(
                "[DRY RUN] Would remove audience mapper %s -> aud:%s",
                action.client_id, action.audience_client_id,
            )
            result.audience_mappers_removed.append(
                (action.client_id, action.audience_client_id)
            )
            continue

        try:
            await client.delete_protocol_mapper(
                client_uuid=client_uuid,
                mapper_id=action.mapper_id,
            )
            result.audience_mappers_removed.append(
                (action.client_id, action.audience_client_id)
            )
        except KeycloakNotFoundError:
            pass  # Already gone
        except Exception as e:
            result.errors.append(
                f"Failed to remove audience mapper {action.audience_client_id} "
                f"from {action.client_id}: {e}"
            )

    # -------------------------------------------------------------------------
    # 9. Delete orphans (if --prune)
    # -------------------------------------------------------------------------

    if prune:
        for client_id in plan.orphan_clients:
            client_uuid = client_uuids.get(client_id)
            if not client_uuid:
                continue

            if dry_run:
                logger.info("[DRY RUN] Would delete orphan client: %s", client_id)
                result.clients_deleted.append(client_id)
                continue

            try:
                await client.delete_client(client_uuid)
                result.clients_deleted.append(client_id)
            except Exception as e:
                result.errors.append(f"Failed to delete client {client_id}: {e}")

        for scope_name in plan.orphan_scopes:
            scope_id = scope_ids.get(scope_name)
            if not scope_id:
                continue

            if dry_run:
                logger.info("[DRY RUN] Would delete orphan scope: %s", scope_name)
                result.scopes_deleted.append(scope_name)
                continue

            try:
                await client.delete_client_scope(scope_id)
                result.scopes_deleted.append(scope_name)
            except Exception as e:
                result.errors.append(f"Failed to delete scope {scope_name}: {e}")

    return result


def write_secrets_file(
    path: Path,
    result: SyncResult,
    config: KeycloakConfig,
) -> None:
    """Write client secrets to a YAML file.

    Args:
        path: Output path for secrets file
        result: Sync result containing secrets
        config: Configuration for realm info
    """
    output = {
        "# WARNING": "This file contains sensitive credentials. DO NOT COMMIT.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "realm": config.realm,
        "clients": {},
    }

    for client_id, secret in result.client_secrets.items():
        output["clients"][client_id] = {
            "client_id": client_id,
            "secret": secret,
            "created": client_id in result.clients_created,
            "updated": client_id in result.clients_updated,
        }

    path.write_text(yaml.safe_dump(output, default_flow_style=False, sort_keys=False))
    logger.info("Wrote secrets to: %s", path)