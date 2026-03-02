"""keycloak bootstrap command.

Usage:
    celine-policies keycloak bootstrap
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Annotated, Optional

import typer
import yaml

from celine.policies.cli.keycloak.client import (
    KeycloakAdminClient,
    KeycloakAuthError,
    KeycloakError,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.policies.cli.keycloak.commands._utils import configure_logging

logger = logging.getLogger(__name__)


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
        Optional[Path],
        typer.Option("--secrets-file", "-s", help="Secrets file path"),
    ] = None,
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
    configure_logging(verbose)

    # Build settings - bootstrap requires admin user credentials
    base = KeycloakSettings()
    settings = base.with_overrides(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        # DO NOT set admin_client_id/secret - force admin user auth
    )

    # Resolve secrets_file: CLI flag > env var (via settings.secrets_file)
    resolved_secrets_file = secrets_file or settings.secrets_file

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
    _update_secrets_file(
        resolved_secrets_file, settings.realm, client_id, secret, created
    )

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

            # Ensure 'roles' scope is assigned (required for resource_access in token)
            typer.echo("Ensuring 'roles' default scope...")
            await client.ensure_default_scope(client_uuid, "roles")

            # Ensure audience mapper is present (token must include realm-management)
            typer.echo("Ensuring realm-management audience mapper...")
            await client.ensure_realm_management_audience_mapper(client_uuid)

            # Ensure service account has the required roles
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

        # Ensure 'roles' scope is assigned (required for resource_access in token)
        typer.echo("Adding 'roles' default scope...")
        await client.ensure_default_scope(client_uuid, "roles")

        # Add audience mapper before assigning roles
        typer.echo("Adding realm-management audience mapper...")
        await client.ensure_realm_management_audience_mapper(client_uuid)

        # Assign realm-management roles
        typer.echo("Assigning realm-management roles...")
        await client.assign_realm_management_roles(client_uuid)

        return secret, True
