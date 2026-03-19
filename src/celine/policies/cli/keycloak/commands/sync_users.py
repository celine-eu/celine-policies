"""keycloak sync-users command.

Usage:
    celine-policies keycloak sync-users [rec_yaml]
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
from celine.policies.cli.keycloak.settings import KeycloakSettings, SyncUsersSettings
from celine.policies.cli.keycloak.commands._utils import (
    configure_logging,
    build_settings,
    load_rec_participants,
    derive_username,
)

logger = logging.getLogger(__name__)


def sync_users(
    # Positional — can also come from CELINE_SYNC_USERS_REC_YAML
    rec_yaml: Annotated[
        Optional[Path],
        typer.Argument(
            help="Path to REC registry YAML  [env: CELINE_SYNC_USERS_REC_YAML]"
        ),
    ] = None,
    # Keycloak connection — default via CELINE_KEYCLOAK_* (KeycloakSettings)
    base_url: Annotated[
        Optional[str],
        typer.Option(
            "--base-url",
            "-u",
            help="Keycloak base URL  [env: CELINE_KEYCLOAK_BASE_URL]",
        ),
    ] = None,
    realm: Annotated[
        Optional[str],
        typer.Option(
            "--realm", "-r", help="Target realm  [env: CELINE_KEYCLOAK_REALM]"
        ),
    ] = None,
    admin_user: Annotated[
        Optional[str],
        typer.Option(
            "--admin-user", help="Admin username  [env: CELINE_KEYCLOAK_ADMIN_USER]"
        ),
    ] = None,
    admin_password: Annotated[
        Optional[str],
        typer.Option(
            "--admin-password",
            help="Admin password  [env: CELINE_KEYCLOAK_ADMIN_PASSWORD]",
        ),
    ] = None,
    admin_client_id: Annotated[
        Optional[str],
        typer.Option(
            "--admin-client-id",
            help="Admin client ID  [env: CELINE_KEYCLOAK_ADMIN_CLIENT_ID]",
        ),
    ] = None,
    admin_client_secret: Annotated[
        Optional[str],
        typer.Option(
            "--admin-client-secret",
            help="Admin client secret  [env: CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET]",
        ),
    ] = None,
    # Behaviour — default via CELINE_SYNC_USERS_* (SyncUsersSettings)
    dry_run: Annotated[
        Optional[bool],
        typer.Option(
            "--dry-run",
            "-n",
            help="Show planned changes without applying  [env: CELINE_SYNC_USERS_DRY_RUN]",
        ),
    ] = None,
    groups: Annotated[
        Optional[list[str]],
        typer.Option(
            "--group",
            "-g",
            help=(
                "Group path to assign (repeatable). "
                "Default: /viewers  [env: CELINE_SYNC_USERS_GROUPS]"
            ),
        ),
    ] = None,
    temp_password: Annotated[
        Optional[str],
        typer.Option(
            "--temp-password",
            "--password",
            help=(
                "Fixed password for all users (also: --password). "
                "Omit for a random password per user.  "
                "[env: CELINE_SYNC_USERS_TEMP_PASSWORD]"
            ),
        ),
    ] = None,
    temporary: Annotated[
        Optional[bool],
        typer.Option(
            "--temporary/--no-temporary",
            help=(
                "Temporary password (forced reset on first login). "
                "Default: true  [env: CELINE_SYNC_USERS_TEMPORARY]"
            ),
        ),
    ] = None,
    verbose: Annotated[
        Optional[bool],
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose output  [env: CELINE_SYNC_USERS_VERBOSE]",
        ),
    ] = None,
    reset_password: Annotated[
        bool,
        typer.Option(
            "--reset-password",
            help="Reset password on existing users too (not just newly created ones)",
        ),
    ] = False,
    mock: Annotated[
        bool,
        typer.Option(
            "--mock",
            help="Fill email (<username>@celine.localhost), firstName, lastName, emailVerified for dev convenience.",
        ),
    ] = False,
    secrets_file: Annotated[
        Optional[Path],
        typer.Option("--secrets-file", "-s", help="Path to secrets file for auth"),
    ] = None,
) -> None:
    """Ensure Keycloak users exist for every participant in a REC registry YAML.

    Reads the REC YAML, checks each participant's user_id against Keycloak,
    and creates any missing users with a temporary password (forced reset on
    first login) and the specified group memberships.

    Group resolution happens before any user is created — the command fails
    immediately if a group path does not exist, rather than leaving partially
    provisioned users behind.

    This command is idempotent — safe to run multiple times.

    All options have sensible defaults and can be set via environment variables
    so the command can run with no flags at all in a configured environment.

    Examples:
        # zero-flag run if env vars are already set
        celine-policies keycloak sync-users

        # explicit YAML, dry run
        celine-policies keycloak sync-users greenland.yaml --dry-run

        # admin-user auth
        celine-policies keycloak sync-users greenland.yaml \\
            --admin-user admin --admin-password admin

        # multiple groups, fixed password for a demo handout
        celine-policies keycloak sync-users greenland.yaml \\
            --group /viewers --group /community-gl \\
            --temp-password "Demo@2025"

        # fully env-driven (CI/CD, docker-compose)
        CELINE_KEYCLOAK_BASE_URL=https://kc.example.com \\
        CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET=xxx \\
        CELINE_SYNC_USERS_REC_YAML=greenland.yaml \\
        CELINE_SYNC_USERS_GROUPS="/viewers /community-gl" \\
        CELINE_SYNC_USERS_TEMP_PASSWORD="Demo@2025" \\
        celine-policies keycloak sync-users
    """
    # Build settings objects — CLI flags override env/defaults
    sync_settings = SyncUsersSettings().with_overrides(
        rec_yaml=rec_yaml,
        groups=groups,
        temp_password=temp_password,
        temporary=temporary,
        dry_run=dry_run,
        verbose=verbose,
    )

    configure_logging(sync_settings.verbose)

    kc_settings = build_settings(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
        secrets_file=secrets_file,
    )

    # Resolve YAML path — argument > env var
    resolved_yaml = sync_settings.rec_yaml
    if resolved_yaml is None:
        typer.secho(
            "Error: REC YAML path required. Pass as argument or set "
            "CELINE_SYNC_USERS_REC_YAML.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)
    if not resolved_yaml.exists():
        typer.secho(
            f"Error: file not found: {resolved_yaml}", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(1)

    try:
        participants = load_rec_participants(resolved_yaml)
    except Exception as e:
        typer.secho(f"Error reading REC YAML: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    if not participants:
        typer.secho(
            "No participants with user_id found in YAML.", fg=typer.colors.YELLOW
        )
        raise typer.Exit(0)

    typer.echo(f"REC YAML : {resolved_yaml} — {len(participants)} participant(s)")
    typer.echo(f"Keycloak : {kc_settings.base_url}  realm={kc_settings.realm}")
    typer.echo(f"Groups   : {', '.join(sync_settings.groups)}")
    typer.echo(
        f"Password : {'fixed' if sync_settings.temp_password else 'random per user'}"
    )
    if sync_settings.dry_run:
        typer.secho("\n[DRY RUN] No changes will be applied.\n", fg=typer.colors.YELLOW)

    try:
        created, skipped, errors = asyncio.run(
            _async_sync_users(
                kc_settings=kc_settings,
                sync_settings=sync_settings,
                participants=participants,
                reset_password=reset_password,
                temporary=sync_settings.temporary,
                mock=mock,
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
        if sync_settings.verbose:
            import traceback

            traceback.print_exc()
        raise typer.Exit(1)

    typer.echo("\nDone.")
    typer.secho(f"  Created : {len(created)}", fg=typer.colors.GREEN)
    typer.echo(f"  Skipped : {len(skipped)} (already exist)")
    if errors:
        typer.secho(f"  Errors  : {len(errors)}", fg=typer.colors.RED)
        for err in errors:
            typer.secho(f"    - {err}", fg=typer.colors.RED)
        raise typer.Exit(1)


async def _async_sync_users(
    kc_settings: "KeycloakSettings",
    sync_settings: "SyncUsersSettings",
    participants: list[dict],
    reset_password: bool = False,
    temporary: bool = True,
    mock: bool = False,
) -> tuple[list[str], list[str], list[str]]:
    """Check and create Keycloak users for the given participant list.

    Returns (created, skipped, errors).
    """
    created: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []

    async with KeycloakAdminClient(kc_settings) as kc:
        await kc.authenticate()

        # Resolve group paths → IDs up front.
        # Fail fast: better to error before touching any user than to create
        # users and then silently skip the group assignment.
        group_ids: dict[str, str] = {}  # path -> keycloak uuid
        for path in sync_settings.groups:
            group = await kc.get_group_by_path(path)
            if not group:
                raise KeycloakError(
                    f"Group '{path}' not found in realm '{kc_settings.realm}'. "
                    f"Create it first or remove it from --group."
                )
            group_ids[path] = group["id"]
            logger.debug("Resolved group %s -> %s", path, group["id"])

        for p in participants:
            user_id = p["user_id"]
            key = p["key"]
            username = derive_username(key)

            pwd = sync_settings.generate_password()

            if sync_settings.dry_run:
                existing = await kc.get_user_by_username(username)
                if existing:
                    typer.echo(f"  ✓ {key} — exists as '{existing.get('username')}'")
                    skipped.append(username)
                else:
                    typer.secho(
                        f"  ~ {key} username='{username}' groups={list(group_ids.keys())}",
                        fg=typer.colors.YELLOW,
                    )
                    created.append(username)
                continue

            try:
                email = f"{username}@celine.localhost" if mock else None
                name = username if mock else None
                kc_uuid, was_created = await kc.ensure_user(
                    username=username,
                    email=email,
                    first_name=name,
                    last_name=name,
                    email_verified=mock,
                    temporary_password=pwd,
                    temporary=temporary,
                )

                if not was_created:
                    if reset_password and not sync_settings.dry_run:
                        await kc.set_user_password(kc_uuid, pwd, temporary=temporary)
                        typer.echo(
                            f"  ✓ {key} — already exists ({kc_uuid}), password reset"
                        )
                    else:
                        typer.echo(f"  ✓ {key} — already exists ({kc_uuid})")
                    skipped.append(username)
                    continue

                for path, gid in group_ids.items():
                    await kc.add_user_to_group_with_retry(kc_uuid, gid)

                typer.secho(
                    f"  + {key} username='{username}' uuid={kc_uuid} pwd='{pwd}'"
                    f" groups={list(group_ids.keys())}",
                    fg=typer.colors.GREEN,
                )
                created.append(username)

            except Exception as e:
                msg = f"{key} ({username}): {e}"
                typer.secho(f"  ✗ {msg}", fg=typer.colors.RED)
                errors.append(msg)

    return created, skipped, errors
