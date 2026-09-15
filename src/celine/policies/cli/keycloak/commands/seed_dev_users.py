"""keycloak seed-dev-users command.

Usage:
    ENV=dev celine-policies keycloak seed-dev-users [config/keycloak/dev-users.yaml]

The development users the dev realm import carried (admin, manager, editor, viewer), for a
realm that did not come from that import (requester, 2026-09-14). Users level, and
development only: it refuses unless ENV names a non-production environment, because every
password in the file is public.

Idempotent. An absent user is created with its password, verified email and group; an
existing one is only put back in its group. A password is never reset.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
import yaml

from celine.policies.cli.keycloak.client import (
    KeycloakAdminClient,
    KeycloakAuthError,
    KeycloakError,
)
from celine.policies.cli.keycloak.commands._utils import build_settings, configure_logging
from celine.policies.cli.keycloak.settings import KeycloakSettings

DEFAULT_DEV_USERS_FILE = Path("config/keycloak/dev-users.yaml")
_FIELDS = {"username", "email", "first_name", "last_name", "password", "group"}


def load_dev_users(path: Path) -> list[dict[str, Any]]:
    """Read and check the file. Every user needs a username, a password and a group path."""
    data = yaml.safe_load(path.read_text()) or {}
    users = data.get("users")
    if not isinstance(users, list) or not users:
        raise ValueError(f"{path}: expected a non-empty `users:` list")
    for i, user in enumerate(users):
        if not isinstance(user, dict):
            raise ValueError(f"{path}: users[{i}] must be a mapping")
        unknown = set(user) - _FIELDS
        if unknown:
            raise ValueError(f"{path}: users[{i}] has unknown key(s) {sorted(unknown)}")
        for key in ("username", "password", "group"):
            if not user.get(key):
                raise ValueError(f"{path}: users[{i}] needs `{key}`")
        if not str(user["group"]).startswith("/"):
            raise ValueError(f"{path}: users[{i}].group must be a group path like /admins")
    return users


def seed_dev_users(
    users_file: Annotated[
        Path, typer.Argument(help="Development users file")
    ] = DEFAULT_DEV_USERS_FILE,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", "-n", help="Show what would change without writing")
    ] = False,
    base_url: Annotated[
        Optional[str], typer.Option("--base-url", "-u", help="Keycloak base URL")
    ] = None,
    realm: Annotated[Optional[str], typer.Option("--realm", "-r", help="Target realm")] = None,
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
        Optional[str], typer.Option("--admin-client-secret", help="Admin service client secret")
    ] = None,
    secrets_file: Annotated[
        Optional[Path], typer.Option("--secrets-file", "-s", help="Path to secrets file for auth")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output")] = False,
) -> None:
    """Create the development users (admin, manager, editor, viewer). Development realms only."""
    configure_logging(verbose)

    if KeycloakSettings().is_production:
        typer.secho(
            "Error: seed-dev-users runs only on a development realm: its passwords are "
            "public. Set ENV=dev (or local, test, ci) if this is one.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)

    try:
        users = load_dev_users(users_file)
    except (OSError, ValueError, yaml.YAMLError) as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    settings = build_settings(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
        secrets_file=secrets_file,
    )
    typer.echo(f"Users    : {users_file} ({len(users)})")
    typer.echo(f"Keycloak : {settings.base_url}  realm={settings.realm}")

    try:
        created, joined = asyncio.run(_async_seed(settings, users, dry_run))
    except KeycloakAuthError as e:
        typer.secho(f"Authentication failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    except KeycloakError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    state = "would be created" if dry_run else "created"
    if not created and not joined:
        typer.echo("  ✓ no change")
    for username in created:
        typer.secho(f"  + {username} {state}", fg=typer.colors.GREEN)
    for username, group in joined:
        typer.secho(f"  + {username} -> {group}", fg=typer.colors.GREEN)


async def _async_seed(
    settings: KeycloakSettings, users: list[dict[str, Any]], dry_run: bool
) -> tuple[list[str], list[tuple[str, str]]]:
    created: list[str] = []
    joined: list[tuple[str, str]] = []
    async with KeycloakAdminClient(settings) as kc:
        await kc.authenticate()

        # The role groups are platform level: checked for every user before any write.
        group_ids: dict[str, str] = {}
        for path in sorted({u["group"] for u in users}):
            group = await kc.get_group_by_path(path)
            if group is None:
                raise KeycloakError(
                    f"group {path} does not exist. Run `celine-policies keycloak bootstrap` "
                    f"first: platform.yaml declares the role groups."
                )
            group_ids[path] = group["id"]

        for user in users:
            existing = await kc.get_user_by_username(user["username"])
            if existing is None:
                created.append(user["username"])
                joined.append((user["username"], user["group"]))
                if dry_run:
                    continue
                user_id, _ = await kc.ensure_user(
                    user["username"],
                    email=user.get("email"),
                    first_name=user.get("first_name"),
                    last_name=user.get("last_name"),
                    temporary_password=str(user["password"]),
                    temporary=False,
                    email_verified=True,
                )
                await kc.add_user_to_group(user_id, group_ids[user["group"]])
                continue

            paths = {g.get("path") for g in await kc.get_user_groups(existing["id"])}
            if user["group"] not in paths:
                joined.append((user["username"], user["group"]))
                if not dry_run:
                    await kc.add_user_to_group(existing["id"], group_ids[user["group"]])
    return created, joined
