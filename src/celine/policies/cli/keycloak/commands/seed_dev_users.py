"""keycloak seed-dev-users command.

Usage:
    ENV=dev celine-policies keycloak seed-dev-users [config/keycloak/dev-users.yaml]

The development users for a local realm (requester, 2026-09-14), under the two-level model
(ADR-0012): a user may hold the realm role `platform-admin`, and groups inside organizations.
No realm group: realm groups carry no authority. Users level, and development only: it
refuses unless ENV is exactly `dev`, because every password in the file is public.

Idempotent. An absent user is created with its password and verified email; every user is
then given its declared realm roles and organization groups if it lacks them. Nothing is
taken away, and a password is never reset.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
import yaml
from celine.sdk.auth import PLATFORM_ADMIN_ROLE

from celine.policies.cli.keycloak.client import (
    ROLE_HIERARCHY,
    KeycloakAdminClient,
    KeycloakAuthError,
    KeycloakError,
)
from celine.policies.cli.keycloak.commands._utils import build_settings, configure_logging
from celine.policies.cli.keycloak.settings import KeycloakSettings

DEFAULT_DEV_USERS_FILE = Path("config/keycloak/dev-users.yaml")
_FIELDS = {"username", "email", "first_name", "last_name", "password", "realm_roles", "organizations"}
#: The realm roles a development user may hold: the platform-wide grant, and nothing else.
DEV_REALM_ROLES = frozenset({PLATFORM_ADMIN_ROLE})


def load_dev_users(path: Path) -> list[dict[str, Any]]:
    """Read and check the file.

    Every user needs a username and a password. `realm_roles` may name only
    `platform-admin`; `organizations` maps an organization alias to one of its groups
    (admins, managers, editors, viewers). A realm group (`group:`) is refused.
    """
    data = yaml.safe_load(path.read_text()) or {}
    users = data.get("users")
    if not isinstance(users, list) or not users:
        raise ValueError(f"{path}: expected a non-empty `users:` list")
    for i, user in enumerate(users):
        if not isinstance(user, dict):
            raise ValueError(f"{path}: users[{i}] must be a mapping")
        if "group" in user:
            raise ValueError(
                f"{path}: users[{i}] names a realm group; realm groups carry no authority "
                f"(ADR-0012). Use realm_roles: [{PLATFORM_ADMIN_ROLE}] or organizations:"
            )
        unknown = set(user) - _FIELDS
        if unknown:
            raise ValueError(f"{path}: users[{i}] has unknown key(s) {sorted(unknown)}")
        for key in ("username", "password"):
            if not user.get(key):
                raise ValueError(f"{path}: users[{i}] needs `{key}`")
        roles = user.setdefault("realm_roles", [])
        if not isinstance(roles, list) or not set(roles) <= DEV_REALM_ROLES:
            raise ValueError(
                f"{path}: users[{i}].realm_roles may name only {sorted(DEV_REALM_ROLES)}, got {roles!r}"
            )
        orgs = user.setdefault("organizations", {})
        if not isinstance(orgs, dict) or not all(
            isinstance(alias, str) and alias and group in ROLE_HIERARCHY for alias, group in orgs.items()
        ):
            raise ValueError(
                f"{path}: users[{i}].organizations must map an organization alias to one of "
                f"{ROLE_HIERARCHY}, got {orgs!r}"
            )
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
    """Create the development users (admin, org-admin, org-viewer). Development realms only."""
    configure_logging(verbose)

    if KeycloakSettings().is_production:
        typer.secho(
            "Error: seed-dev-users runs only on a development realm: its passwords are "
            "public. Set ENV=dev if this is one.",
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
    for username, what in joined:
        typer.secho(f"  + {username} -> {what}", fg=typer.colors.GREEN)


async def _async_seed(
    settings: KeycloakSettings, users: list[dict[str, Any]], dry_run: bool
) -> tuple[list[str], list[tuple[str, str]]]:
    created: list[str] = []
    joined: list[tuple[str, str]] = []
    async with KeycloakAdminClient(settings) as kc:
        await kc.authenticate()

        # Everything the users join is resolved before any write: the role is platform
        # level (`bootstrap`), the organizations and their groups are `sync-users`'.
        for role in sorted({r for u in users for r in u["realm_roles"]}):
            if await kc.get_realm_role(role) is None:
                raise KeycloakError(
                    f"realm role {role} does not exist. Run `celine-policies keycloak bootstrap` "
                    f"first: platform.yaml declares it."
                )
        orgs: dict[str, str] = {}
        org_groups: dict[tuple[str, str], str] = {}
        for user in users:
            for alias, group_name in user["organizations"].items():
                if alias not in orgs:
                    org = await kc.get_organization_by_alias(alias)
                    if org is None:
                        raise KeycloakError(
                            f"organization {alias} does not exist. Create it first "
                            f"(`celine-policies keycloak sync-users` with the example REC)."
                        )
                    orgs[alias] = org["id"]
                if (alias, group_name) not in org_groups:
                    group = await kc.get_org_group_by_name(orgs[alias], group_name)
                    if group is None:
                        raise KeycloakError(f"organization {alias} has no group {group_name}")
                    org_groups[(alias, group_name)] = group["id"]

        for user in users:
            existing = await kc.get_user_by_username(user["username"])
            user_id = existing["id"] if existing else None
            if existing is None:
                created.append(user["username"])
                if not dry_run:
                    user_id, _ = await kc.ensure_user(
                        user["username"],
                        email=user.get("email"),
                        first_name=user.get("first_name"),
                        last_name=user.get("last_name"),
                        temporary_password=str(user["password"]),
                        temporary=False,
                        email_verified=True,
                    )

            held = await kc.get_user_realm_role_names(user_id) if user_id else set()
            for role in user["realm_roles"]:
                if role not in held:
                    joined.append((user["username"], f"realm role {role}"))
                    if not dry_run:
                        await kc.add_user_realm_role(user_id, role)

            for alias, group_name in user["organizations"].items():
                org_id, group_id = orgs[alias], org_groups[(alias, group_name)]
                if user_id and await kc.is_user_in_org_group(org_id, group_id, user_id):
                    continue
                joined.append((user["username"], f"{alias}/{group_name}"))
                if not dry_run:
                    await kc.ensure_user_in_organization(org_id, user_id)
                    await kc.ensure_user_in_org_group(org_id, group_id, user_id)
    return created, joined
