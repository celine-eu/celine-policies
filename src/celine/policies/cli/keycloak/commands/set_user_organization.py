"""keycloak set-user-organization command.

Usage:
    celine-policies keycloak set-user-organization <username> \
        --organization myorg1 --organization orgB \
        --group admin --group manager
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


def set_user_organization(
    username: Annotated[str, typer.Argument(help="Username to assign")],
    organizations: Annotated[
        list[str],
        typer.Option("--organization", "-o", help="Organization alias (repeatable)"),
    ],
    groups: Annotated[
        Optional[list[str]],
        typer.Option("--group", "-g", help="Organization group to assign (repeatable)"),
    ] = None,
    # Connection options
    base_url: Annotated[
        Optional[str], typer.Option("--base-url", "-u", help="Keycloak base URL")
    ] = None,
    realm: Annotated[
        Optional[str], typer.Option("--realm", help="Target realm")
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
    dry_run: Annotated[
        bool, typer.Option("--dry-run", "-n", help="Preview changes without applying")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose output")
    ] = False,
    secrets_file: Annotated[
        Optional[Path],
        typer.Option("--secrets-file", "-s", help="Path to secrets file for auth"),
    ] = None,
) -> None:
    """Assign a user to organizations with optional org-level groups.

    Idempotent: safe to run multiple times. The user, organizations, and groups
    must already exist in Keycloak. The user is added to each organization if
    not already a member, and added to each group in every organization.

    Examples:
        celine-policies keycloak set-user-organization user1 -o myorg1 -o orgB -g admin -g manager
        celine-policies keycloak set-user-organization user1 -o myorg1
        celine-policies keycloak set-user-organization user1 -o myorg1 -g viewers --dry-run
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
        asyncio.run(
            _async_set_user_organization(
                settings, username, organizations, groups or [], dry_run
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
        raise typer.Exit(1)


async def _async_set_user_organization(
    settings,
    username: str,
    org_aliases: list[str],
    group_names: list[str],
    dry_run: bool,
) -> None:
    async with KeycloakAdminClient(settings) as kc:
        await kc.authenticate()

        # --- resolve user ---
        user = await kc.get_user_by_username(username)
        if not user:
            typer.secho(f"User not found: {username}", fg=typer.colors.RED, err=True)
            raise typer.Exit(1)
        user_id = user["id"]

        # --- resolve organizations and validate groups exist ---
        resolved: list[tuple[str, str, dict[str, str]]] = []  # (alias, org_id, {group_name: group_id})
        for alias in org_aliases:
            org = await kc.get_organization_by_alias(alias)
            if not org:
                typer.secho(
                    f"Organization not found: {alias}", fg=typer.colors.RED, err=True
                )
                raise typer.Exit(1)
            org_id = org["id"]

            group_map: dict[str, str] = {}
            for gn in group_names:
                grp = await kc.get_org_group_by_name(org_id, gn)
                if not grp:
                    typer.secho(
                        f"Group '{gn}' not found on organization '{alias}'",
                        fg=typer.colors.RED,
                        err=True,
                    )
                    raise typer.Exit(1)
                group_map[gn] = grp["id"]

            resolved.append((alias, org_id, group_map))

        if dry_run:
            typer.secho("Dry-run mode — no changes applied", fg=typer.colors.YELLOW)
            for alias, _, group_map in resolved:
                typer.echo(f"  would add '{username}' to organization '{alias}'")
                for gn in group_map:
                    typer.echo(f"  would add '{username}' to group '{gn}' in '{alias}'")
            return

        # --- apply ---
        for alias, org_id, group_map in resolved:
            added = await kc.ensure_user_in_organization(org_id, user_id)
            if added:
                typer.secho(
                    f"✓ Added '{username}' to organization '{alias}'",
                    fg=typer.colors.GREEN,
                )
            else:
                typer.echo(f"  '{username}' already in organization '{alias}'")

            for gn, gid in group_map.items():
                assigned = await kc.ensure_user_in_org_group(org_id, gid, user_id)
                if assigned:
                    typer.secho(
                        f"✓ Added '{username}' to group '{gn}' in '{alias}'",
                        fg=typer.colors.GREEN,
                    )
                else:
                    typer.echo(
                        f"  '{username}' already in group '{gn}' in '{alias}'"
                    )
