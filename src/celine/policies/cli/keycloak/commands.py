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
    SyncResult,
    apply_sync_plan,
    compute_sync_plan,
    write_secrets_file,
)


from celine.policies.cli.keycloak.settings import (
    KeycloakSettings,
    SyncUsersSettings,
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


def _load_rec_participants(rec_yaml: Path) -> list[dict]:
    """Extract participant records from a REC registry YAML.

    Returns a list of dicts with keys: user_id, key, name.
    Participants without a user_id are skipped with a warning.
    """
    raw = yaml.safe_load(rec_yaml.read_text())
    participants_raw = raw.get("participants", {})

    participants = []
    for key, data in participants_raw.items():
        user_id = data.get("user_id")
        if not user_id:
            logger.warning("Participant %s has no user_id — skipping", key)
            continue
        participants.append(
            {
                "key": key,
                "user_id": user_id,
                "name": data.get("name", key),
            }
        )
    return participants


def _derive_username(participant_key: str) -> str:
    """Stable Keycloak username from the participant key (e.g. 'gl-00001').

    Unique within the community, no PII, safe to hand out during demos.
    """
    return participant_key.lower()


# ---------------------------------------------------------------------------
# sync-users command                                                      # <<< NEW
# ---------------------------------------------------------------------------


@keycloak_app.command("sync-users")
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
            help=(
                "Fixed temporary password for all users. "
                "Omit for a random password per user.  "
                "[env: CELINE_SYNC_USERS_TEMP_PASSWORD]"
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
        dry_run=dry_run,
        verbose=verbose,
    )

    _configure_logging(sync_settings.verbose)

    kc_settings = _build_settings(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
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
        participants = _load_rec_participants(resolved_yaml)
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
            username = _derive_username(key)

            existing = await kc.get_user_by_id(user_id)
            if existing:
                typer.echo(
                    f"  ✓ {key} ({user_id}) — exists as '{existing.get('username')}'"
                )
                skipped.append(user_id)
                continue

            pwd = sync_settings.generate_password()

            if sync_settings.dry_run:
                typer.secho(
                    f"  ~ {key} ({user_id})"
                    f" username='{username}'"
                    f" groups={list(group_ids.keys())}",
                    fg=typer.colors.YELLOW,
                )
                created.append(user_id)
                continue

            try:
                await kc.create_user(
                    user_id=user_id,
                    username=username,
                    temporary_password=pwd,
                )
                for path, gid in group_ids.items():
                    await kc.add_user_to_group(user_id, gid)

                typer.secho(
                    f"  + {key} ({user_id})"
                    f" username='{username}'"
                    f" pwd='{pwd}'"
                    f" groups={list(group_ids.keys())}",
                    fg=typer.colors.GREEN,
                )
                created.append(user_id)

            except Exception as e:
                msg = f"{key} ({user_id}): {e}"
                typer.secho(f"  ✗ {msg}", fg=typer.colors.RED)
                errors.append(msg)

    return created, skipped, errors
