"""keycloak set-password command.

Usage:
    celine-policies keycloak set-password <username> <password>
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
from celine.policies.cli.keycloak.commands._utils import (
    configure_logging,
    build_settings,
)

logger = logging.getLogger(__name__)


def set_password(
    username: Annotated[str, typer.Argument(help="Username to update")],
    password: Annotated[str, typer.Argument(help="New password")],
    # Connection options
    base_url: Annotated[
        Optional[str], typer.Option("--base-url", "-u", help="Keycloak base URL")
    ] = None,
    realm: Annotated[
        Optional[str], typer.Option("--realm", "-r", help="Target realm")
    ] = None,
    admin_user: Annotated[
        Optional[str], typer.Option("--admin-user", help="Keycloak admin username")
    ] = None,
    admin_password: Annotated[
        Optional[str], typer.Option("--admin-password", help="Keycloak admin password")
    ] = None,
    admin_client_id: Annotated[
        Optional[str], typer.Option("--admin-client-id", help="Admin service client ID")
    ] = None,
    admin_client_secret: Annotated[
        Optional[str],
        typer.Option("--admin-client-secret", help="Admin service client secret"),
    ] = None,
    temporary: Annotated[
        bool,
        typer.Option(
            "--temporary/--permanent", help="Force password change on next login"
        ),
    ] = True,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose output")
    ] = False,
    secrets_file: Annotated[
        Optional[Path],
        typer.Option("--secrets-file", "-s", help="Path to secrets file for auth"),
    ] = None,
) -> None:
    """Set the password for a Keycloak user.

    Examples:
        celine-policies keycloak set-password ah-00001 Demo@2025
        celine-policies keycloak set-password ah-00001 Demo@2025 --permanent
    """
    configure_logging(verbose)

    settings = build_settings(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
        secrets_file=secrets_file,
    )

    try:
        asyncio.run(_async_set_password(settings, username, password, temporary))
    except KeycloakAuthError as e:
        typer.secho(f"Authentication failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    except KeycloakError as e:
        typer.secho(f"Keycloak error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)


async def _async_set_password(
    settings,
    username: str,
    password: str,
    temporary: bool,
) -> None:
    async with KeycloakAdminClient(settings) as kc:
        await kc.authenticate()

        user = await kc.get_user_by_username(username)
        if not user:
            typer.secho(f"User not found: {username}", fg=typer.colors.RED, err=True)
            raise typer.Exit(1)

        await kc.set_user_password(user["id"], password, temporary=temporary)

        mode = "temporary" if temporary else "permanent"
        typer.secho(
            f"✓ Password updated for '{username}' ({mode})", fg=typer.colors.GREEN
        )
