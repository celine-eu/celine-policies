"""keycloak sync-test-accounts command (REQ-0023, ADR-0016).

Usage:
    ENV=staging celine-policies keycloak sync-test-accounts test-accounts.yaml --dry-run
    ENV=staging CELINE_KEYCLOAK_TEST_ACCOUNT_PASSWORD_TEMPLATE=... \
        celine-policies keycloak sync-test-accounts test-accounts.yaml [--rotate]

Converges the target realm's (`CELINE_KEYCLOAK_*`) test accounts on the declaration: one
account per declared user in `/test-accounts`, with a placeholder profile and exactly the
declared realm role and organization groups; a test account no longer declared is disabled.
See `celine.policies.cli.keycloak.test_accounts`.

Exit codes:
    0  converged
    1  refused (ENV not dev, staging or preprod; a malformed declaration or template; no
       template where one is needed; a /test-accounts group this command did not make) or
       failed (Keycloak error)
    2  ran, but a declared account could not be converged: a collision with an account
       outside /test-accounts, a missing organization or group, a password the realm's
       policy refused, a password mode that differs from the declared one, or a managed
       organization membership
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from celine.policies.cli.keycloak.client import (
    KeycloakAdminClient,
    KeycloakAuthError,
    KeycloakError,
)
from celine.policies.cli.keycloak.commands._utils import build_settings, configure_logging
from celine.policies.cli.keycloak.settings import KeycloakSettings, password_for_test_account
from celine.policies.cli.keycloak.test_accounts import (
    COUNTS,
    TestAccountsRefused,
    TestAccountsReport,
    load_test_accounts,
    refusal,
    sync_test_accounts,
)

#: Exit code of a run that could not converge every declared account.
EXIT_ATTENTION = 2


def _fail(message: str) -> None:
    typer.secho(f"Error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(1)


def sync_test_accounts_command(
    declaration: Annotated[Path, typer.Argument(help="Test accounts declaration (users: [...])")],
    rotate: Annotated[
        bool,
        typer.Option("--rotate", help="Reset every enabled fixed test account's password from the template"),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", "-n", help="Report what would change; write nothing")
    ] = False,
    base_url: Annotated[str | None, typer.Option("--base-url", "-u", help="Keycloak base URL")] = None,
    realm: Annotated[str | None, typer.Option("--realm", "-r", help="Target realm")] = None,
    admin_client_id: Annotated[
        str | None, typer.Option("--admin-client-id", help="Realm admin client ID")
    ] = None,
    admin_client_secret: Annotated[
        str | None, typer.Option("--admin-client-secret", help="Realm admin client secret")
    ] = None,
    secrets_file: Annotated[
        Path | None, typer.Option("--secrets-file", "-s", help="Path to secrets file for auth")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output")] = False,
) -> None:
    """Keep the declared test accounts on this non-prod realm (ENV dev, staging or preprod).

    Accounts are marked by /test-accounts and carry a placeholder profile; their realm role
    and organization groups are set to exactly what is declared. Accounts outside
    /test-accounts are never touched; a test account is disabled, never deleted. Prints
    usernames and counts, never a password.
    """
    configure_logging(verbose)
    why = refusal(KeycloakSettings().env)
    if why:
        _fail(why)
    try:
        password_for_test_account("x")
    except ValueError as e:
        _fail(str(e))
    try:
        accounts = load_test_accounts(declaration)
    except ValueError as e:
        _fail(str(e))

    settings = build_settings(
        base_url=base_url,
        realm=realm,
        admin_user=None,
        admin_password=None,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
        secrets_file=secrets_file,
    )
    typer.echo(f"Accounts : {declaration} ({len(accounts)})")
    typer.echo(f"Keycloak : {settings.base_url}  realm={settings.realm}")
    if dry_run:
        typer.secho("Dry run: nothing is written", fg=typer.colors.YELLOW)

    try:
        report = asyncio.run(_run(settings, accounts, dry_run, rotate))
    except KeycloakAuthError as e:
        _fail(f"authentication failed: {e}")
    except (KeycloakError, TestAccountsRefused) as e:
        _fail(str(e))

    _print(report, dry_run)
    if report.needs_attention:
        raise typer.Exit(EXIT_ATTENTION)


async def _run(settings, accounts, dry_run: bool, rotate: bool) -> TestAccountsReport:
    async with KeycloakAdminClient(settings) as kc:
        await kc.authenticate()
        return await sync_test_accounts(
            kc, accounts, password_for=password_for_test_account, dry_run=dry_run, rotate=rotate
        )


def _print(report: TestAccountsReport, dry_run: bool) -> None:
    """Usernames, what changed, and counts: never a password."""
    prefix = "would: " if dry_run else ""
    for username, what in report.changes:
        typer.echo(f"  {prefix}{username}: {what}")
    for name in COUNTS:
        typer.echo(f"  {name}: {report.counts[name]}")
    if report.missing_organizations:
        typer.echo(f"  not found: {', '.join(sorted(report.missing_organizations))}")
