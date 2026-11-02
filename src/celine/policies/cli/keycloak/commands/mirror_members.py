"""keycloak mirror-members command (REQ-0021, ADR-0015).

Usage:
    ENV=staging celine-policies keycloak mirror-members \
        --source-url https://api.<prod>/rec-registry \
        --source-issuer https://keycloak.<prod>/realms/celine
    ENV=staging celine-policies keycloak mirror-members --from-file mirror.json \
        --source-issuer https://keycloak.<prod>/realms/celine --dry-run

Mirrors the source realm's members into the target realm (`CELINE_KEYCLOAK_*`): id = the
member's account subject, username = the member key, nothing personal. See
`celine.policies.cli.keycloak.member_mirror`.

Exit codes:
    0  converged (a dry run: nothing to report beyond counts)
    1  refused (ENV is prod or unset, the target is the source's Keycloak, a missing or
       double source, no secret) or failed (source unreadable or malformed, Keycloak error)
    2  ran, but a member could not be mirrored: a collision with an account the mirror did
       not make, a username held by another mirror, a changed key, a contradiction in the
       export, a community without an organization, or an impersonator not found
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
from celine.policies.cli.keycloak.commands._utils import (
    build_settings,
    configure_logging,
)
from celine.policies.cli.keycloak.member_mirror import (
    COUNTS,
    MirrorRefused,
    MirrorReport,
    MirrorSourceError,
    fetch_mirror_export,
    mirror_members,
    parse_mirror_export,
    read_mirror_file,
    refusal,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings, MemberMirrorSettings

#: Exit code of a run that could not mirror every member (see the module docstring).
EXIT_ATTENTION = 2


def _fail(message: str) -> None:
    typer.secho(f"Error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(1)


def mirror_members_command(
    from_file: Annotated[
        Path | None,
        typer.Option("--from-file", "-f", help="Read the export from a JSON file (CELINE_MEMBER_MIRROR_FILE)"),
    ] = None,
    source_url: Annotated[
        str | None,
        typer.Option("--source-url", help="Source registry base URL (CELINE_MEMBER_MIRROR_SOURCE_URL)"),
    ] = None,
    source_issuer: Annotated[
        str | None,
        typer.Option(
            "--source-issuer",
            help="Source realm issuer URL, required (CELINE_MEMBER_MIRROR_SOURCE_ISSUER)",
        ),
    ] = None,
    source_client_id: Annotated[
        str | None,
        typer.Option(
            "--source-client-id",
            help="Source realm client (CELINE_MEMBER_MIRROR_SOURCE_CLIENT_ID, default svc-member-mirror)",
        ),
    ] = None,
    impersonators: Annotated[
        list[str] | None,
        typer.Option(
            "--impersonator",
            help="Target username that may impersonate the mirrors, repeatable "
            "(CELINE_MEMBER_MIRROR_IMPERSONATORS, space-separated)",
        ),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", "-n", help="Count what would change; write nothing")
    ] = False,
    base_url: Annotated[
        str | None, typer.Option("--base-url", "-u", help="Target Keycloak base URL")
    ] = None,
    realm: Annotated[str | None, typer.Option("--realm", "-r", help="Target realm")] = None,
    admin_client_id: Annotated[
        str | None, typer.Option("--admin-client-id", help="Target admin client ID")
    ] = None,
    admin_client_secret: Annotated[
        str | None, typer.Option("--admin-client-secret", help="Target admin client secret")
    ] = None,
    secrets_file: Annotated[
        Path | None, typer.Option("--secrets-file", "-s", help="Path to secrets file for auth")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output")] = False,
) -> None:
    """Mirror the source realm's members into this (non-prod) realm. Never runs on prod.

    One account per member with an account subject: id = subject, username = member key,
    no e-mail, name or credential, in the community's organization and its viewers group,
    enabled while the member is active. Accounts the mirror did not make are never
    touched; a mirror is disabled, never deleted. Prints counts only.
    """
    configure_logging(verbose)
    mirror = MemberMirrorSettings()
    issuer = source_issuer or mirror.source_issuer
    file = from_file or mirror.file
    url = source_url or mirror.source_url
    client_id = source_client_id or mirror.source_client_id
    names = impersonators if impersonators else (mirror.impersonators or [])

    if not issuer:
        _fail("--source-issuer (CELINE_MEMBER_MIRROR_SOURCE_ISSUER) is required: it names the source realm")
    target_url = base_url or KeycloakSettings().base_url
    why = refusal(env=KeycloakSettings().env, target_base_url=target_url, source_issuer=issuer)
    if why:
        _fail(why)
    if file and url:
        _fail("give one source: --from-file or --source-url, not both")
    if not file and not url:
        _fail("no source: --source-url (CELINE_MEMBER_MIRROR_SOURCE_URL) or --from-file")
    secret = mirror.source_client_secret.get_secret_value() if mirror.source_client_secret else None
    if url and not secret:
        _fail(f"reading {url} needs CELINE_MEMBER_MIRROR_SOURCE_CLIENT_SECRET, the secret of '{client_id}'")

    try:
        if file:
            data = read_mirror_file(file)
        else:
            data = asyncio.run(
                fetch_mirror_export(source_url=url, issuer=issuer, client_id=client_id, client_secret=secret)
            )
        members = parse_mirror_export(data)
    except MirrorSourceError as e:
        _fail(f"source: {e}")

    settings = build_settings(
        base_url=base_url,
        realm=realm,
        admin_user=None,
        admin_password=None,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
        secrets_file=secrets_file,
    )
    typer.echo(f"Source   : {'file' if file else url}  issuer={issuer}")
    typer.echo(f"Keycloak : {settings.base_url}  realm={settings.realm}")
    if dry_run:
        typer.secho("Dry run: nothing is written", fg=typer.colors.YELLOW)

    try:
        report = asyncio.run(_run(settings, members, issuer, dry_run, names))
    except KeycloakAuthError as e:
        _fail(f"authentication failed: {e}")
    except (KeycloakError, MirrorRefused) as e:
        _fail(str(e))

    _print(report)
    if report.needs_attention:
        raise typer.Exit(EXIT_ATTENTION)


async def _run(settings, members, issuer: str, dry_run: bool, names: list[str]) -> MirrorReport:
    async with KeycloakAdminClient(settings) as kc:
        await kc.authenticate()
        return await mirror_members(kc, members, source=issuer, dry_run=dry_run, impersonators=names)


def _print(report: MirrorReport) -> None:
    """Counts, and the communities that have no organization: never a member."""
    for name in COUNTS:
        typer.echo(f"  {name}: {report.counts[name]}")
    if report.missing_organizations:
        typer.echo(f"  organizations not found: {', '.join(sorted(report.missing_organizations))}")
