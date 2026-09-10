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
    overlay: Annotated[
        Optional[list[Path]],
        typer.Option(
            "--overlay",
            help=(
                "Further file declaring part of the same realm; repeatable. "
                "Merged with the configuration file before anything is synced."
            ),
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
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

    Defaults to ENV=prod, which refuses to sync a client whose secret is still the
    clients.yaml placeholder (a secret equal to the client id, or an empty one).
    Export ENV=dev to accept those fallbacks on a local realm.

    A grant naming a scope no file declares is also refused, in any environment,
    before anything is authenticated.

    One realm may be declared by more than one file. `--overlay` is repeatable and
    every file is merged before the sync sees any of it, because a file describing
    only part of a realm does not leave the rest alone: `sync` recomputes the grants
    of every client it finds, so syncing half the declaration silently narrows the
    clients it does mention, with no flag and nothing deleted. A client's identity
    is declared by exactly one file; any file may add grants to a client another
    file declares.

    Example:
        celine-policies keycloak sync config/keycloak.yaml --dry-run
        celine-policies keycloak sync config/keycloak.yaml --admin-user admin --admin-password admin
        celine-policies keycloak sync clients.yaml --overlay clients.ds.yaml
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

    # Load configuration. Every file is merged into one declaration first, so
    # the placeholder-secret guard and the scope-reference check below see the
    # whole realm rather than one file's view of it.
    overlays = list(overlay or [])
    try:
        config = KeycloakConfig.from_yaml_files([config_path, *overlays])
    except Exception as e:
        typer.secho(f"Error loading config: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    # Override realm from config if not specified on CLI
    if config.realm and not realm:
        settings = settings.with_overrides(realm=config.realm)

    typer.echo(f"Syncing to Keycloak: {settings.base_url} realm={settings.realm}")
    if overlays:
        typer.echo(
            f"Merged {len(overlays) + 1} files: "
            + ", ".join(str(path) for path in [config_path, *overlays])
        )
    typer.echo(f"Config: {len(config.scopes)} scopes, {len(config.clients)} clients")
    typer.echo(f"Environment: {settings.env}")

    # Refuse to write dev placeholder secrets into a production realm. Checked
    # before authenticating so a misconfigured deployment fails on its own
    # machine rather than halfway through rewriting a live realm.
    if settings.is_production:
        _fail_on_placeholder_secrets(config)

    # Refuse a grant naming a scope no file declares. Like the guard above, this
    # runs before authenticating: the failure it replaces happened *after* the
    # realm had been rewritten.
    _fail_on_undefined_scopes(config)

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


def _fail_on_placeholder_secrets(config: KeycloakConfig) -> None:
    """Abort the sync if any client would be given a dev placeholder secret.

    `clients.yaml` writes secrets as `${SVC_X_SECRET:-svc-x}`, so an unset
    variable resolves to the client_id itself. Locally that is the whole point;
    in a production realm it is a client credential anyone can derive from the
    client list, and nothing downstream would ever complain about it.

    Raises typer.Exit(1) — the failure has to be loud, and it names every
    offending client and the variable that fixes it.
    """
    offenders = config.clients_with_placeholder_secrets()
    if not offenders:
        return

    typer.secho(
        f"\nRefusing to sync: {len(offenders)} client(s) have a placeholder secret "
        "and ENV is not a development environment.",
        fg=typer.colors.RED,
        err=True,
    )
    for client_id in offenders:
        source = config.secret_source(client_id)
        hint = f"set {source}" if source else "set an explicit secret in the config"
        typer.secho(f"  ! {client_id} — {hint}", fg=typer.colors.RED, err=True)

    typer.secho(
        "\nA secret equal to the client_id (or an empty one) is guessable from the "
        "client list alone.\nSet the variables above, or export ENV=dev if this is "
        "a local realm and the defaults are intended.",
        fg=typer.colors.YELLOW,
        err=True,
    )
    raise typer.Exit(1)


def _fail_on_undefined_scopes(config: KeycloakConfig) -> None:
    """Abort the sync if any client is granted a scope nobody declares.

    This used to be a yellow warning, and the sync proceeded. It did not end
    well: the scope is never created, so `apply_sync_plan` reaches the
    assignment, cannot resolve the name, and appends `Scope not found` to
    `result.errors` — which fails the command **after** every client, scope and
    mapper before it has already been written. A realm half-rewritten by a run
    that then exits 1 is the worst of the three possible outcomes.

    It became fatal when one realm stopped being one file. With a single file a
    dangling grant is a typo the author sees; across two, it is the ordinary
    consequence of a grant staying in one file while its scope moves to the
    other, and it is the specific mistake the split makes possible. So it fails
    here, before anything is authenticated, and names both the scope and the
    clients that asked for it — there is no flag to accept it, because there is
    no realm in which the grant means anything.
    """
    undefined = config.validate_scope_references()
    if not undefined:
        return

    askers: dict[str, list[str]] = {}
    for client in config.clients:
        for scope_name in list(client.default_scopes) + list(client.optional_scopes):
            if scope_name in undefined:
                askers.setdefault(scope_name, []).append(client.client_id)

    typer.secho(
        f"\nRefusing to sync: {len(undefined)} scope(s) are granted but declared "
        "by no file.",
        fg=typer.colors.RED,
        err=True,
    )
    for scope_name in undefined:
        wanted_by = ", ".join(sorted(set(askers.get(scope_name, []))))
        typer.secho(f"  ! {scope_name} — granted to {wanted_by}", fg=typer.colors.RED, err=True)

    typer.secho(
        "\nKeycloak would never create these scopes, so every grant above would be "
        "skipped\nand the services would get a 403 the first time they needed it. "
        "Declare them,\nor supply the file that does with --overlay.",
        fg=typer.colors.YELLOW,
        err=True,
    )
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

        # Provision realm claim scopes (organization, groups, dataspace) — idempotent
        if not dry_run:
            claim_changed = await client.ensure_realm_claim_scopes(config.oauth2_proxy_client)
            if claim_changed:
                typer.echo("  ! realm claim scopes (organization, groups, dataspace) provisioned")

        # Fetch current state
        typer.echo("Fetching current state...")
        current = await client.fetch_current_state()

        # What each service account may already administer. One realm read on a
        # realm that does not use the feature, which then returns having found
        # nothing — but it is read unconditionally so that a client dropping its
        # `admin_permissions` block still has the grant taken away.
        await client.fetch_admin_permission_state(current, config.get_client_ids())

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
