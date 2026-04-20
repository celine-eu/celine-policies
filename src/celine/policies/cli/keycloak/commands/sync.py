"""keycloak sync command.

Usage:
    celine-policies keycloak sync <config.yaml>
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Annotated, Optional

import typer

from celine.policies.cli.keycloak.client import (
    KeycloakAdminClient,
    KeycloakAuthError,
    KeycloakError,
)
from celine.policies.cli.keycloak.models import KeycloakConfig
from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.policies.cli.keycloak.sync import (
    SyncResult,
    apply_sync_plan,
    compute_sync_plan,
    write_secrets_file,
)
from celine.policies.cli.keycloak.commands._utils import (
    configure_logging,
    build_settings,
)

logger = logging.getLogger(__name__)


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
    configure_logging(verbose)

    # Build settings
    settings = build_settings(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
        secrets_file=secrets_file,
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
    async with KeycloakAdminClient(settings) as client:
        # Authenticate
        await client.authenticate()

        # Provision realm claim scopes (organization, groups) — idempotent
        if not dry_run:
            claim_changed = await client.ensure_realm_claim_scopes(config.oauth2_proxy_client)
            if claim_changed:
                typer.echo("  ! realm claim scopes (organization, groups) provisioned")

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
