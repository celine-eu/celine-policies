"""keycloak bootstrap command.

Usage:
    celine-policies keycloak bootstrap [platform.yaml] [--overlay FILE ...] [--dry-run | --check]
        [--export FILE] [--allow-destructive]

The platform level of the realm, and nothing else (plan each-cli-command-owns-one-level):

0. **The realm itself**, created empty if it does not exist. That needs the master admin.
1. **The platform declaration** (`platform.yaml`, see `keycloak/platform.py`): realm
   features, sign-in settings, languages, themes, lifespans, brute force, the realm role
   `platform-admin` and who holds it, and the retired realm groups and roles it deletes
   (ADR-0012). Only the declared keys are written. A deployment overrides a listed key with
   `CELINE_KEYCLOAK_PLATFORM_<KEY>`, or stops declaring it with the value `null`.
   Also the built-in `account-console` client's default client scopes, added when missing
   (an imported realm has none, and the account console answers 403).
   And the realm's browser flow: the platform admin's second factor (REQ-0015, ADR-0013),
   on unless `ENV=dev`.
2. **The admin CLI client** — the service account every other command authenticates as.
   Created or refreshed only through master, because a service account cannot create the
   client it is.
3. **The master realm** (REQ-0016, ADR-0014, `keycloak/master.py`). `bootstrap` signs in to
   master as its own client `svc-celine-policies-bootstrap` (secret
   `CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET`), or as the master admin user when that fails;
   converges the client; then does everything else with the client's token. Outside dev it
   hardens master with that token only: brute force, and a second factor for its admins.
   Outside dev the client's secret is required.

With the admin CLI client's own credentials instead (the environment, or the secrets
file a first run wrote — in dev, or when asked: REQ-0020), and master not to be hardened
(dev), step 1 runs and steps 2 and 3 are skipped: the client holds `manage-realm`, which
every platform setting needs (measured on 26.7.3).

For a deployment job (decision 2): `--export` writes a partial export of the realm before
any write, `--check` plans and exits 1 if anything would change, and outside dev a plan that
turns a setting off or narrows a list is refused without `--allow-destructive`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Annotated, Optional

import typer

from celine.policies.cli.keycloak.admin_mfa import apply_admin_mfa, plan_admin_mfa
from celine.policies.cli.keycloak.client import (
    KeycloakAdminClient,
    KeycloakAuthError,
    KeycloakError,
)
from celine.policies.cli.keycloak.master import (
    MASTER_REALM,
    apply_bootstrap_client,
    apply_master_hardening,
    plan_bootstrap_client,
    plan_master_hardening,
    require_bootstrap_client,
    sign_in_to_master,
)
from celine.sdk.auth import PLATFORM_ADMIN_ROLE

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
    secrets_file_to_write,
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
        typer.Option(
            "--secrets-file",
            "-s",
            help=(
                "Record the admin CLI client's secret in this file (mode 0600). "
                "Also CELINE_KEYCLOAK_SECRETS_FILE. Without either, only ENV=dev "
                "records it, in .client.secrets.yaml."
            ),
        ),
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

    The admin CLI client's secret is written to disk only when asked, as `sync`
    does: `--secrets-file PATH` or `CELINE_KEYCLOAK_SECRETS_FILE`. ENV=dev writes
    `.client.secrets.yaml` without being asked; any other environment writes
    nothing and says where the secret can be read instead. The file is mode 0600.

    Example:
        celine-policies keycloak bootstrap --admin-user admin --admin-password admin
    """
    configure_logging(verbose)
    dry_run = dry_run or check

    try:
        declaration = load_platform(platform_yaml, overlay or [], os.environ)
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
    # Where the admin CLI client's secret goes, or None (REQ-0020). Decided before
    # any Keycloak call, from the flag and the environment only.
    secrets_output = secrets_file_to_write(secrets_file, settings)

    # Outside dev master is hardened, and only the bootstrap client may do it (REQ-0016):
    # refused here, before Keycloak is asked anything.
    problem = settings.bootstrap_secret_problem()
    if problem:
        typer.secho(f"Error: {problem}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    # Through master: the bootstrap client, or the master admin user when it is absent.
    through_master = settings.has_admin_credentials or bool(settings.bootstrap_secret)
    if through_master:
        # `authenticate` prefers the admin CLI client's credentials, so a secret in the
        # environment would otherwise win over master.
        settings = settings.model_copy(update={"admin_client_secret": None})
    else:
        settings = settings.with_auto_secret()
        if not settings.has_client_credentials:
            typer.secho(
                "Error: bootstrap needs credentials. Use the bootstrap client "
                "(CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET) or --admin-user and "
                "--admin-password (required the first time, and to refresh the admin CLI "
                "client), or the admin CLI client's own (CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET "
                "or the secrets file) to converge the platform only.",
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
                manage_admin_client=through_master,
                dry_run=dry_run,
                export=export,
                allow_destructive=allow_destructive or not settings.is_production,
                admin_mfa=settings.admin_mfa,
                harden_master=settings.master_hardened,
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

    if not through_master:
        typer.echo(
            f"\nAdmin CLI client: skipped ({client_id} cannot refresh itself; "
            f"configure the bootstrap client, or pass --admin-user and --admin-password, "
            f"to create or refresh it)"
        )
        return

    secret, created = admin_client
    if dry_run:
        state = "would be created" if created else "exists, would be refreshed"
        typer.echo(f"\nAdmin CLI client: {client_id} {state}")
        return

    if secrets_output is not None:
        _update_secrets_file(secrets_output, settings.realm, client_id, secret, created)

    shown = secret if not settings.is_production else REDACTED
    action = "Created" if created else "Retrieved existing"
    typer.secho(f"\n✓ {action} client: {client_id}", fg=typer.colors.GREEN)
    typer.echo(f"  Secret: {shown}")
    if secrets_output is not None:
        typer.echo(f"  Secrets file: {secrets_output}")
    else:
        typer.echo(
            "  Secrets file: not written (pass --secrets-file or set "
            "CELINE_KEYCLOAK_SECRETS_FILE to record it)"
        )
    typer.echo("\nSet environment variables for future operations:")
    typer.secho(
        f"  export CELINE_KEYCLOAK_ADMIN_CLIENT_ID={client_id}", fg=typer.colors.CYAN
    )
    if settings.is_production:
        where = (
            f"in {secrets_output}"
            if secrets_output is not None
            else (
                f"from the realm {settings.realm}: admin console, Clients > {client_id} "
                f"> Credentials"
            )
        )
        typer.secho(
            f"  export CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET=<the secret for {client_id} "
            f"{where}>",
            fg=typer.colors.CYAN,
        )
        if secrets_output is None:
            typer.echo(
                "  or keep CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET set: the other "
                "commands sign in as the bootstrap client when the admin CLI "
                "client's secret is not set."
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
        _report_platform_admins(result)
        _report_master(result, dry_run=dry_run)
        return
    for change in result.settings + result.smtp:
        mark = "!" if destructive(change) else "~"
        note = "  [destructive]" if mark == "!" else ""
        typer.secho(
            f"  {mark} {change.key}: {change.current!r} -> {change.desired!r}  ({change.source}){note}",
            fg=typer.colors.YELLOW,
        )
    for path in result.groups_removed:
        typer.secho(f"  - realm group {path} (retired)", fg=typer.colors.YELLOW)
    for role in result.roles_removed:
        typer.secho(f"  - realm role {role} (retired)", fg=typer.colors.YELLOW)
    if result.platform_admin_role_created:
        typer.secho(f"  + realm role {PLATFORM_ADMIN_ROLE}", fg=typer.colors.GREEN)
    for label in result.platform_admin_unmapped_groups:
        typer.secho(f"  - {PLATFORM_ADMIN_ROLE} mapped onto group {label}", fg=typer.colors.YELLOW)
    for name in result.platform_admin_unmapped_composites:
        typer.secho(f"  - {PLATFORM_ADMIN_ROLE} inside composite role {name}", fg=typer.colors.YELLOW)
    for scope in result.account_console_scopes_added:
        typer.secho(f"  + account-console default scope {scope}", fg=typer.colors.GREEN)
    if result.realm_admin_created:
        typer.secho(f"  + realm admin {result.realm_admin_created}", fg=typer.colors.GREEN)
    for username in result.platform_admins_granted:
        typer.secho(f"  + {username} -> realm role {PLATFORM_ADMIN_ROLE}", fg=typer.colors.GREEN)
    _report_changes(result.admin_mfa)
    _report_platform_admins(result)
    _report_master(result, dry_run=dry_run)


def _report_changes(changes) -> None:
    for change in changes:
        mark = "!" if destructive(change) else "~"
        note = "  [destructive]" if mark == "!" else ""
        typer.secho(
            f"  {mark} {change.key}: {change.current!r} -> {change.desired!r}  ({change.source}){note}",
            fg=typer.colors.YELLOW,
        )


def _report_master(result: PlatformResult, *, dry_run: bool) -> None:
    """The master realm (REQ-0016): who signed in, the bootstrap client, the hardening."""
    if result.master_session is None and result.master_skipped is None:
        return
    verb = "would change" if dry_run else "changed"
    typer.echo(f"\nMaster realm ({verb}):")
    if result.master_session:
        typer.echo(f"  signed in as {result.master_session}")
    _report_changes(result.master_client)
    _report_changes(result.master)
    if result.master_skipped:
        typer.echo(f"  not hardened: {result.master_skipped}")
    if not (result.master_client or result.master):
        typer.echo("  ✓ no change")


def _report_platform_admins(result: PlatformResult) -> None:
    """What a run cannot change and an operator should know: never a change."""
    for username in result.platform_admins_missing:
        typer.secho(
            f"  ? {username}: listed in platform_admin.users but not in the realm yet; "
            f"granted on the first run after it exists",
            fg=typer.colors.YELLOW,
        )
    for username in result.platform_admins_undeclared:
        typer.secho(
            f"  ! {username} holds {PLATFORM_ADMIN_ROLE} but is not declared "
            f"(kept; bootstrap does not revoke a grant given by hand)",
            fg=typer.colors.YELLOW,
        )


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
    admin_mfa: bool = False,
    harden_master: bool = False,
) -> tuple[PlatformResult, tuple[str, bool]]:
    """Sign in, create the realm if absent, converge the platform, master, then the admin
    CLI client.

    `manage_admin_client`: this run goes through master (the bootstrap client, or the master
    admin user), so it may create the realm and the admin CLI client. Otherwise it signs in
    as the admin CLI client and converges the platform only.

    Returns the platform result and `(secret, created)` for the admin client —
    `("", created)` when it was skipped or this is a dry run.
    """
    secret = settings.bootstrap_secret
    if harden_master and not secret:
        # The command refuses this before any call; kept here for any other caller.
        raise PlatformDeclarationError(settings.bootstrap_secret_problem() or "no bootstrap client")

    async with KeycloakAdminClient(settings) as client, KeycloakAdminClient(
        settings.for_realm(MASTER_REALM)
    ) as master:
        master_client_changes: list = []
        master_session: str | None = None
        if manage_admin_client:
            # (i) the bootstrap client first, else the master admin user
            as_client = await sign_in_to_master(master, settings)
            client.adopt_session(master)
            master_session = (
                f"bootstrap client {settings.bootstrap_client_id}" if as_client
                else f"master admin user {settings.admin_user}"
            )
            if secret:
                # (ii) the client, converged to the configured secret and its roles
                plan = await plan_bootstrap_client(
                    master,
                    client_id=settings.bootstrap_client_id,
                    secret=secret,
                    signed_in_as_client=as_client,
                )
                master_client_changes = plan.changes
                if not dry_run:
                    if master_client_changes:
                        try:
                            await apply_bootstrap_client(master, plan, secret=secret)
                        except KeycloakError as e:
                            if as_client:
                                raise KeycloakError(
                                    f"the bootstrap client could not converge itself ({e}). "
                                    f"Restore it as a master administrator (kc.sh bootstrap-admin, "
                                    f"docs/deployment.md)"
                                ) from e
                            raise
                    # (iii) everything else as the client, its token checked
                    await master.authenticate_master_client(settings.bootstrap_client_id, secret)
                    client.adopt_session(master)
                    master_session = f"bootstrap client {settings.bootstrap_client_id}"
        else:
            await client.authenticate()

        # (iv) master's hardening, planned before any write to the platform realm
        master_plan = None
        if harden_master:
            master_plan = await plan_master_hardening(
                master, declaration, brute_force=settings.brute_force_protected, mfa=admin_mfa
            )

        def finish(result: PlatformResult) -> PlatformResult:
            result.master_client = master_client_changes
            result.master_session = master_session
            if master_plan is not None:
                result.master = master_plan.changes
            elif manage_admin_client:
                result.master_skipped = "ENV=dev (CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED and _ADMIN_MFA_REQUIRED off)"
            return result

        realm_created = False
        if not await client.realm_exists():
            if not manage_admin_client:
                raise KeycloakError(
                    f"realm '{settings.realm}' does not exist; creating it needs the master "
                    f"admin (--admin-user and --admin-password) or the bootstrap client"
                )
            if dry_run:
                return finish(PlatformResult(realm_created=True)), ("", True)
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
        mfa_plan = await plan_admin_mfa(
            client,
            required=admin_mfa,
            role=declaration.platform_admin_role,
            retired_roles=declaration.retired_roles,
            browser_flow=(await client.get_realm_settings()).get("browserFlow"),
        )
        platform.admin_mfa = mfa_plan.changes
        finish(platform)
        if not dry_run:
            if platform.destructive and not allow_destructive:
                raise PlatformDeclarationError(
                    "the plan turns off or narrows "
                    f"{[c.key for c in platform.destructive]}; outside dev that needs "
                    "--allow-destructive on this run"
                )
            platform = await converge_platform(client, declaration, dry_run=False, **converge)
            if mfa_plan.changes:
                await apply_admin_mfa(client, mfa_plan)
            platform.admin_mfa = mfa_plan.changes
            if master_plan is not None:
                # Refuses any token but the bootstrap client's own, checked in this run.
                require_bootstrap_client(master, settings.bootstrap_client_id)
                await apply_master_hardening(master, master_plan, client_id=settings.bootstrap_client_id)
            finish(platform)
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
