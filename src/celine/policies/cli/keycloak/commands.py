"""Keycloak CLI commands.

Commands:
    celine-policies keycloak sync <config.yaml>
    celine-policies keycloak bootstrap
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
import yaml

from celine.policies.cli.keycloak.client import (
    KeycloakAdminClient,
    KeycloakAuthError,
    KeycloakConflictError,
    KeycloakError,
)
from celine.policies.cli.keycloak.models import KeycloakConfig
from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.policies.cli.keycloak.sync import (
    apply_sync_plan,
    compute_sync_plan,
    write_secrets_file,
)

logger = logging.getLogger(__name__)

keycloak_app = typer.Typer(
    name="keycloak",
    help="Keycloak management commands",
    add_completion=False,
)


def _configure_logging(verbose: bool) -> None:
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet down httpx
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def _build_settings(
    base_url: str | None,
    realm: str | None,
    admin_user: str | None,
    admin_password: str | None,
    admin_client_id: str | None,
    admin_client_secret: str | None,
) -> KeycloakSettings:
    """Build settings from environment, CLI overrides, and auto-load from secrets file."""
    base = KeycloakSettings()
    settings = base.with_overrides(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
    )

    # Auto-load secret from .client.secrets.yaml if not provided
    settings = settings.with_auto_secret()

    return settings


@keycloak_app.command("sync")
def sync(
    config_path: Path = typer.Argument(
        help="Path to Keycloak configuration YAML file",
        exists=True,
        dir_okay=False,
        readable=True,
        default=Path("./clients.yaml"),
    ),
    # Connection options
    base_url: Annotated[
        Optional[str],
        typer.Option("--base-url", "-u", help="Keycloak base URL"),
    ] = None,
    realm: Annotated[
        Optional[str],
        typer.Option("--realm", "-r", help="Target realm"),
    ] = None,
    # Admin user auth
    admin_user: Annotated[
        Optional[str],
        typer.Option("--admin-user", help="Keycloak admin username"),
    ] = None,
    admin_password: Annotated[
        Optional[str],
        typer.Option("--admin-password", help="Keycloak admin password"),
    ] = None,
    # Service client auth
    admin_client_id: Annotated[
        Optional[str],
        typer.Option("--admin-client-id", help="Admin service client ID"),
    ] = None,
    admin_client_secret: Annotated[
        Optional[str],
        typer.Option("--admin-client-secret", help="Admin service client secret"),
    ] = None,
    # Sync options
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run", "-n", help="Show what would be done without making changes"
        ),
    ] = False,
    prune: Annotated[
        bool,
        typer.Option("--prune", help="Delete orphaned resources not in config"),
    ] = False,
    secrets_file: Annotated[
        Optional[Path],
        typer.Option("--secrets-file", "-s", help="Output file for client secrets"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose output"),
    ] = False,
) -> None:
    """Sync Keycloak scopes and clients to match configuration.

    Reads a YAML configuration file and ensures Keycloak matches the desired state.
    This command is idempotent - running it multiple times has the same effect.

    Example:
        celine-policies keycloak sync config/keycloak.yaml --dry-run
        celine-policies keycloak sync config/keycloak.yaml --admin-user admin --admin-password admin
    """
    _configure_logging(verbose)

    # Build settings
    settings = _build_settings(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
    )

    # Load configuration
    try:
        config = KeycloakConfig.from_yaml(config_path)
    except Exception as e:
        typer.secho(f"Error loading config: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    # Override realm from config if not specified on CLI
    if config.realm and not realm:
        settings = settings.with_overrides(realm=config.realm)

    typer.echo(f"Syncing to Keycloak: {settings.base_url} realm={settings.realm}")
    typer.echo(f"Config: {len(config.scopes)} scopes, {len(config.clients)} clients")

    # Validate scope references
    undefined = config.validate_scope_references()
    if undefined:
        typer.secho(
            f"Warning: Scopes referenced but not defined: {', '.join(undefined)}",
            fg=typer.colors.YELLOW,
        )

    # Run async sync
    try:
        result = asyncio.run(
            _async_sync(
                settings=settings,
                config=config,
                dry_run=dry_run,
                prune=prune,
            )
        )
    except KeycloakAuthError as e:
        typer.secho(f"Authentication failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    except KeycloakError as e:
        typer.secho(f"Keycloak error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        raise typer.Exit(1)

    # Write secrets file
    if result.client_secrets and not dry_run:
        output_path = secrets_file or Path(".client.secrets.yaml")
        write_secrets_file(output_path, result, config)
        typer.echo(f"Secrets written to: {output_path}")

    # Print summary
    typer.echo("\n" + result.summary())

    if not result.success:
        raise typer.Exit(1)


async def _async_sync(
    settings: KeycloakSettings,
    config: KeycloakConfig,
    dry_run: bool,
    prune: bool,
) -> "SyncResult":
    """Run the async sync operation."""
    from celine.policies.cli.keycloak.sync import SyncResult

    async with KeycloakAdminClient(settings) as client:
        # Authenticate
        await client.authenticate()

        # Fetch current state
        typer.echo("Fetching current state...")
        current = await client.fetch_current_state()
        typer.echo(
            f"Found {len(current.scopes)} scopes, {len(current.clients)} clients"
        )

        # Compute sync plan
        plan = compute_sync_plan(config, current)

        # Show plan
        typer.echo("\n" + plan.summary())

        if not plan.has_changes and not (prune and plan.has_orphans):
            return SyncResult()

        if dry_run:
            typer.secho("\n[DRY RUN] No changes applied", fg=typer.colors.YELLOW)
            # Create a mock result for dry run
            result = SyncResult()
            result.scopes_created = [a.scope.name for a in plan.scopes_to_create]
            result.scopes_updated = [a.scope.name for a in plan.scopes_to_update]
            result.clients_created = [
                a.client.client_id for a in plan.clients_to_create
            ]
            result.clients_updated = [
                a.client.client_id for a in plan.clients_to_update
            ]
            return result

        # Confirm if pruning
        if prune and plan.has_orphans:
            typer.secho(
                "\nWarning: --prune will delete orphaned resources!",
                fg=typer.colors.YELLOW,
            )
            if not typer.confirm("Continue?"):
                raise typer.Abort()

        # Apply changes
        typer.echo("\nApplying changes...")
        result = await apply_sync_plan(
            client=client,
            plan=plan,
            config=config,
            current=current,
            prune=prune,
            dry_run=False,
        )

        return result


@keycloak_app.command("bootstrap")
def bootstrap(
    # Connection options
    base_url: Annotated[
        Optional[str],
        typer.Option("--base-url", "-u", help="Keycloak base URL"),
    ] = None,
    realm: Annotated[
        Optional[str],
        typer.Option("--realm", "-r", help="Target realm"),
    ] = None,
    # Admin user auth (required for bootstrap)
    admin_user: Annotated[
        Optional[str],
        typer.Option("--admin-user", help="Keycloak admin username"),
    ] = None,
    admin_password: Annotated[
        Optional[str],
        typer.Option("--admin-password", help="Keycloak admin password"),
    ] = None,
    # Output client
    client_id: Annotated[
        str,
        typer.Option("--client-id", help="Client ID for the admin CLI client"),
    ] = "celine-admin-cli",
    secrets_file: Annotated[
        Path,
        typer.Option("--secrets-file", "-s", help="Secrets file path"),
    ] = Path(".client.secrets.yaml"),
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose output"),
    ] = False,
) -> None:
    """Bootstrap the admin CLI client for Keycloak management.

    Creates a service account client with realm-management roles that can be used
    for subsequent sync operations instead of admin user credentials.

    If the client already exists (in Keycloak or in .client.secrets.yaml),
    retrieves the existing secret and updates the secrets file.

    Example:
        celine-policies keycloak bootstrap --admin-user admin --admin-password admin
    """
    _configure_logging(verbose)

    # Build settings - bootstrap requires admin user credentials
    base = KeycloakSettings()
    settings = base.with_overrides(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        # DO NOT set admin_client_id/secret - force admin user auth
    )

    if not settings.has_admin_credentials:
        typer.secho(
            "Error: Bootstrap requires admin credentials. "
            "Use --admin-user and --admin-password.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)

    typer.echo(f"Bootstrapping admin client: {client_id}")
    typer.echo(f"Keycloak: {settings.base_url} realm={settings.realm}")

    try:
        secret, created = asyncio.run(
            _async_bootstrap(
                settings=settings,
                client_id=client_id,
            )
        )
    except KeycloakAuthError as e:
        typer.secho(f"Authentication failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    except KeycloakError as e:
        typer.secho(f"Keycloak error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        raise typer.Exit(1)

    # Update secrets file
    _update_secrets_file(secrets_file, settings.realm, client_id, secret, created)

    action = "Created" if created else "Retrieved existing"
    typer.secho(f"\n✓ {action} client: {client_id}", fg=typer.colors.GREEN)
    typer.echo(f"  Secret: {secret}")
    typer.echo(f"  Secrets file: {secrets_file}")
    typer.echo("\nSet environment variables for future operations:")
    typer.secho(
        f"  export CELINE_KEYCLOAK_ADMIN_CLIENT_ID={client_id}", fg=typer.colors.CYAN
    )
    typer.secho(
        f"  export CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET={secret}", fg=typer.colors.CYAN
    )


def _update_secrets_file(
    secrets_file: Path,
    realm: str,
    client_id: str,
    secret: str,
    created: bool,
) -> None:
    """Update or create the secrets file with client credentials."""
    from datetime import datetime, timezone

    # Load existing file if present
    data: dict = {}
    if secrets_file.exists():
        try:
            data = yaml.safe_load(secrets_file.read_text()) or {}
        except Exception:
            data = {}

    # Ensure structure
    if "clients" not in data or not isinstance(data["clients"], dict):
        data["clients"] = {}

    # Update metadata
    data["generated_at"] = datetime.now(timezone.utc).isoformat()
    data["realm"] = realm

    # Update client entry (preserves other clients)
    data["clients"][client_id] = {
        "client_id": client_id,
        "secret": secret,
        "created": created,
    }

    # Add warning comment at top
    content = "# WARNING: This file contains sensitive credentials. DO NOT COMMIT.\n"
    content += yaml.safe_dump(data, default_flow_style=False, sort_keys=False)

    secrets_file.write_text(content)
    logger.info("Updated secrets file: %s", secrets_file)


async def _async_bootstrap(
    settings: KeycloakSettings,
    client_id: str,
) -> tuple[str, bool]:
    """Run the async bootstrap operation.

    Returns:
        Tuple of (secret, created) where created is True if client was newly created.
    """
    async with KeycloakAdminClient(settings) as client:
        # Authenticate with admin user
        await client.authenticate()

        # Check if client already exists
        existing = await client.get_client_by_client_id(client_id)

        if existing:
            typer.echo(f"Client already exists: {client_id}")
            client_uuid = existing["id"]

            # Ensure it has the right roles
            typer.echo("Ensuring realm-management roles...")
            await client.assign_realm_management_roles(client_uuid)

            # Get existing secret
            secret = await client.get_client_secret(client_uuid)
            if not secret:
                typer.echo("Regenerating client secret...")
                secret = await client.regenerate_client_secret(client_uuid)

            return secret, False  # Not newly created

        # Create the client
        typer.echo(f"Creating client: {client_id}")
        client_uuid, secret = await client.create_client(
            client_id=client_id,
            name="CELINE Admin CLI",
            description="Service account for celine-policies keycloak sync",
            service_account_enabled=True,
        )

        # Assign realm-management roles
        typer.echo("Assigning realm-management roles...")
        await client.assign_realm_management_roles(client_uuid)

        return secret, True  # Newly created


@keycloak_app.command("status")
def status(
    # Connection options
    base_url: Annotated[
        Optional[str],
        typer.Option("--base-url", "-u", help="Keycloak base URL"),
    ] = None,
    realm: Annotated[
        Optional[str],
        typer.Option("--realm", "-r", help="Target realm"),
    ] = None,
    # Auth options
    admin_user: Annotated[
        Optional[str],
        typer.Option("--admin-user", help="Keycloak admin username"),
    ] = None,
    admin_password: Annotated[
        Optional[str],
        typer.Option("--admin-password", help="Keycloak admin password"),
    ] = None,
    admin_client_id: Annotated[
        Optional[str],
        typer.Option("--admin-client-id", help="Admin service client ID"),
    ] = None,
    admin_client_secret: Annotated[
        Optional[str],
        typer.Option("--admin-client-secret", help="Admin service client secret"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose output"),
    ] = False,
) -> None:
    """Show current Keycloak state (scopes, clients, assignments).

    Example:
        celine-policies keycloak status
    """
    _configure_logging(verbose)

    settings = _build_settings(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
    )

    typer.echo(f"Keycloak: {settings.base_url} realm={settings.realm}")

    try:
        asyncio.run(_async_status(settings))
    except KeycloakAuthError as e:
        typer.secho(f"Authentication failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    except KeycloakError as e:
        typer.secho(f"Keycloak error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


async def _async_status(settings: KeycloakSettings) -> None:
    """Show current Keycloak status."""
    async with KeycloakAdminClient(settings) as client:
        await client.authenticate()
        current = await client.fetch_current_state()

        typer.echo(f"\nClient Scopes ({len(current.scopes)}):")
        for name in sorted(current.scopes.keys()):
            scope = current.scopes[name]
            desc = scope.get("description", "")
            typer.echo(f"  - {name}" + (f": {desc}" if desc else ""))

        typer.echo(f"\nClients ({len(current.clients)}):")
        for client_id in sorted(current.clients.keys()):
            client_data = current.clients[client_id]
            name = client_data.get("name", "")

            default_scopes = current.client_default_scopes.get(client_id, set())
            optional_scopes = current.client_optional_scopes.get(client_id, set())

            # Filter out builtin scopes for display
            custom_default = default_scopes - KeycloakAdminClient.BUILTIN_SCOPES
            custom_optional = optional_scopes - KeycloakAdminClient.BUILTIN_SCOPES

            typer.echo(
                f"  - {client_id}"
                + (f" ({name})" if name and name != client_id else "")
            )
            if custom_default:
                typer.echo(f"      default: {', '.join(sorted(custom_default))}")
            if custom_optional:
                typer.echo(f"      optional: {', '.join(sorted(custom_optional))}")
