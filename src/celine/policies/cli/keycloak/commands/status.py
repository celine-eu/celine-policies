"""keycloak status command.

Usage:
    celine-policies keycloak status
"""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated, Optional

import typer

from celine.policies.cli.keycloak.client import (
    KeycloakAdminClient,
    KeycloakAuthError,
    KeycloakError,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.policies.cli.keycloak.commands._utils import configure_logging, build_settings

logger = logging.getLogger(__name__)


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
    configure_logging(verbose)

    settings = build_settings(
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
