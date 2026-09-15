"""keycloak bootstrap command.

Usage:
    celine-policies keycloak bootstrap [platform.yaml] [--overlay FILE ...] [--dry-run | --check]
        [--export FILE] [--allow-destructive]

The platform level of the realm, and nothing else (plan each-cli-command-owns-one-level):

0. **The realm itself**, created empty if it does not exist. That needs the master admin.
1. **The platform declaration** (`platform.yaml`, see `keycloak/platform.py`): realm
   features, sign-in settings, languages, themes, lifespans, brute force and the role
   groups. Only the declared keys are written.
2. **The admin CLI client** — the service account every other command authenticates as.
   Created or refreshed only with master admin credentials, because a service account
   cannot create the client it is.

With the admin CLI client's own credentials instead (the environment, or the secrets
file a first run wrote), step 1 runs and step 2 is skipped: the client holds
`manage-realm`, which every platform setting needs (measured on 26.7.3).

For a deployment job (decision 2): `--export` writes a partial export of the realm before
any write, `--check` plans and exits 1 if anything would change, and outside dev a plan that
turns a setting off or narrows a list is refused without `--allow-destructive`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Annotated, Optional

import typer

from celine.policies.cli.keycloak.client import (
    KeycloakAdminClient,
    KeycloakAuthError,
    KeycloakError,
)
from celine.policies.cli.keycloak.platform import (
    DEFAULT_PLATFORM_FILE,
    PlatformDeclaration,
    PlatformDeclarationError,
    PlatformResult,
    converge_platform,
    destructive,
    load_platform,
)
from celine.policies.cli.keycloak.secrets_file import merge_secrets_file
from celine.policies.cli.keycloak.settings import (
    DEFAULT_ADMIN_CLIENT_ID,
    KeycloakSettings,
    RealmAdminSettings,
    SmtpSettings,
)
from celine.policies.cli.keycloak.commands._utils import configure_logging

logger = logging.getLogger(__name__)

REDACTED = "<redacted: set ENV=dev to print it>"


def bootstrap(
    platform_yaml: Annotated[
        Path,
        typer.Argument(help="Platform declaration (default: ./platform.yaml)"),
    ] = DEFAULT_PLATFORM_FILE,
    overlay: Annotated[
        Optional[list[Path]],
        typer.Option(
            "--overlay",
            "-o",
            help="Deployment overlay; may change supportedLocales only. Repeatable, last wins.",
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", "-n", help="Show what would change without writing"),
    ] = False,
    check: Annotated[
        bool,
        typer.Option(
            "--check", help="Dry run that exits 1 if anything would change (a job's self-check)"
        ),
    ] = False,
    export: Annotated[
        Optional[Path],
        typer.Option(
            "--export",
            help="Write a partial export of the realm (no users; secrets masked) here before any write",
        ),
    ] = None,
    allow_destructive: Annotated[
        bool,
        typer.Option(
            "--allow-destructive",
            help="Outside dev, apply a plan that turns a setting off or removes a list entry",
        ),
    ] = False,
    # Connection options
    base_url: Annotated[
        Optional[str],
        typer.Option("--base-url", "-u", help="Keycloak base URL"),
    ] = None,
    realm: Annotated[
        Optional[str],
        typer.Option("--realm", "-r", help="Target realm"),
    ] = None,
    # Admin user auth (required to create or refresh the admin CLI client)
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
    ] = DEFAULT_ADMIN_CLIENT_ID,
    secrets_file: Annotated[
        Optional[Path],
        typer.Option("--secrets-file", "-s", help="Secrets file path"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose output"),
    ] = False,
) -> None:
    """Converge the realm's platform level, and bootstrap the admin CLI client.

    Writes only the keys platform.yaml declares. Every other command checks this
    level and refuses without it, so run bootstrap first, then sync, then
    sync-orgs / sync-users.

    Example:
        celine-policies keycloak bootstrap --admin-user admin --admin-password admin
    """
    configure_logging(verbose)
    dry_run = dry_run or check

    try:
        declaration = load_platform(platform_yaml, overlay or [])
    except PlatformDeclarationError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    base = KeycloakSettings()
    settings = base.with_overrides(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        secrets_file=secrets_file,
    )
    resolved_secrets_file = settings.secrets_file

    as_admin_user = settings.has_admin_credentials
    if as_admin_user:
        # `authenticate` prefers client credentials, so a secret in the environment
        # would otherwise win over the admin user this run was given.
        settings = settings.model_copy(update={"admin_client_secret": None})
    else:
        settings = settings.with_auto_secret()
        if not settings.has_client_credentials:
            typer.secho(
                "Error: bootstrap needs credentials. Use --admin-user and --admin-password "
                "(required the first time, and to refresh the admin CLI client), or the "
                "admin CLI client's own (CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET or the secrets "
                "file) to converge the platform only.",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(1)

    typer.echo(f"Platform : {declaration.platform_file}")
    for path in overlay or []:
        typer.echo(f"Overlay  : {path}")
    typer.echo(f"Keycloak : {settings.base_url}  realm={settings.realm}")
    if dry_run:
        typer.secho("\n[DRY RUN] No changes will be applied.", fg=typer.colors.YELLOW)

    try:
        platform, admin_client = asyncio.run(
            _async_bootstrap(
                settings=settings,
                declaration=declaration,
                client_id=client_id,
                manage_admin_client=as_admin_user,
                dry_run=dry_run,
                export=export,
                allow_destructive=allow_destructive or not settings.is_production,
            )
        )
    except KeycloakAuthError as e:
        typer.secho(f"Authentication failed: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    except (KeycloakError, PlatformDeclarationError) as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        raise typer.Exit(1)

    _report_platform(platform, dry_run=dry_run)
    if export is not None and not platform.realm_created:
        typer.echo(f"\nExport   : {export}")

    if check:
        if platform.changed:
            typer.secho("\nCheck failed: the realm differs from the declaration.", fg=typer.colors.RED, err=True)
            raise typer.Exit(1)
        typer.secho("\nCheck passed: nothing to change.", fg=typer.colors.GREEN)
        return

    if not as_admin_user:
        typer.echo(
            f"\nAdmin CLI client: skipped ({client_id} cannot refresh itself; "
            f"pass --admin-user and --admin-password to create or refresh it)"
        )
        return

    secret, created = admin_client
    if dry_run:
        state = "would be created" if created else "exists, would be refreshed"
        typer.echo(f"\nAdmin CLI client: {client_id} {state}")
        return

    _update_secrets_file(resolved_secrets_file, settings.realm, client_id, secret, created)

    shown = secret if not settings.is_production else REDACTED
    action = "Created" if created else "Retrieved existing"
    typer.secho(f"\n✓ {action} client: {client_id}", fg=typer.colors.GREEN)
    typer.echo(f"  Secret: {shown}")
    typer.echo(f"  Secrets file: {resolved_secrets_file}")
    typer.echo("\nSet environment variables for future operations:")
    typer.secho(
        f"  export CELINE_KEYCLOAK_ADMIN_CLIENT_ID={client_id}", fg=typer.colors.CYAN
    )
    if settings.is_production:
        typer.secho(
            f"  export CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET=<the secret for {client_id} "
            f"in {resolved_secrets_file}>",
            fg=typer.colors.CYAN,
        )
    else:
        typer.secho(
            f"  export CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET={secret}", fg=typer.colors.CYAN
        )


def _report_platform(result: PlatformResult, *, dry_run: bool) -> None:
    verb = "would change" if dry_run else "changed"
    typer.echo(f"\nPlatform level ({verb}):")
    if result.realm_created:
        state = "would be created; nothing else can be planned until it exists" if dry_run else "created"
        typer.secho(f"  + realm {state}", fg=typer.colors.GREEN)
    if result.smtp_password_applied:
        # Never the value, in any environment: nothing compares it, so nothing needs it.
        state = "would be sent" if dry_run else "sent"
        typer.echo(f"  = smtpServer.password: write-only, {state} on every run (not compared)")
    if not result.changed:
        typer.echo("  ✓ no change")
        return
    for change in result.settings + result.smtp:
        mark = "!" if destructive(change) else "~"
        note = "  [destructive]" if mark == "!" else ""
        typer.secho(
            f"  {mark} {change.key}: {change.current!r} -> {change.desired!r}  ({change.source}){note}",
            fg=typer.colors.YELLOW,
        )
    for role in result.roles_created:
        typer.secho(f"  + realm role {role}", fg=typer.colors.GREEN)
    for path in result.groups_created:
        typer.secho(f"  + group {path}", fg=typer.colors.GREEN)
    for path, role in result.role_mappings_added:
        typer.secho(f"  + {path} -> realm role {role}", fg=typer.colors.GREEN)
    if result.realm_admin_created:
        typer.secho(f"  + realm admin {result.realm_admin_created}", fg=typer.colors.GREEN)
    if result.realm_admin_group_added:
        user, group = result.realm_admin_group_added
        typer.secho(f"  + {user} -> group {group}", fg=typer.colors.GREEN)


def _update_secrets_file(
    secrets_file: Path,
    realm: str,
    client_id: str,
    secret: str,
    created: bool,
) -> None:
    """Put this client's credentials in the store, preserving the others.

    Merging is not this function's own arrangement with the file: `sync` writes
    the same store through the same writer, which is what stops one command
    deleting the other's credentials.
    """
    merge_secrets_file(
        secrets_file,
        realm,
        {
            client_id: {
                "client_id": client_id,
                "secret": secret,
                "created": created,
            }
        },
    )


async def _async_bootstrap(
    settings: KeycloakSettings,
    declaration: PlatformDeclaration,
    client_id: str,
    manage_admin_client: bool,
    dry_run: bool,
    export: Path | None = None,
    allow_destructive: bool = True,
) -> tuple[PlatformResult, tuple[str, bool]]:
    """Create the realm if absent, converge the platform, then the admin CLI client.

    Returns the platform result and `(secret, created)` for the admin client —
    `("", created)` when it was skipped or this is a dry run.
    """
    async with KeycloakAdminClient(settings) as client:
        await client.authenticate()

        realm_created = False
        if not await client.realm_exists():
            if not manage_admin_client:
                raise KeycloakError(
                    f"realm '{settings.realm}' does not exist; creating it needs the master "
                    f"admin (--admin-user and --admin-password)"
                )
            if dry_run:
                return PlatformResult(realm_created=True), ("", True)
            await client.create_realm()
            realm_created = True
        elif export is not None:
            export.write_text(json.dumps(await client.partial_export(), indent=1, sort_keys=True))

        converge = dict(
            brute_force_protected=settings.brute_force_protected,
            smtp=SmtpSettings(),
            realm_admin=RealmAdminSettings(),
        )
        platform = await converge_platform(client, declaration, dry_run=True, **converge)
        if not dry_run:
            if platform.destructive and not allow_destructive:
                raise PlatformDeclarationError(
                    "the plan turns off or narrows "
                    f"{[c.key for c in platform.destructive]}; outside dev that needs "
                    "--allow-destructive on this run"
                )
            platform = await converge_platform(client, declaration, dry_run=False, **converge)
        platform.realm_created = realm_created

        if not manage_admin_client:
            return platform, ("", False)

        existing = await client.get_client_by_client_id(client_id)
        if dry_run:
            return platform, ("", existing is None)

        return platform, await _ensure_admin_client(client, client_id, existing)


async def _ensure_admin_client(
    client: KeycloakAdminClient,
    client_id: str,
    existing: dict | None,
) -> tuple[str, bool]:
    """Create or refresh the admin CLI client. Returns (secret, created)."""
    if existing:
        typer.echo(f"\nClient already exists: {client_id}")
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

        return secret, False

    typer.echo(f"\nCreating client: {client_id}")
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
