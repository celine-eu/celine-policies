"""keycloak sync-users command.

Usage:
    celine-policies keycloak sync-users [rec_yaml]
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Optional

import typer
import yaml

from celine.policies.cli.keycloak.client import (
    KeycloakAdminClient,
    KeycloakAuthError,
    KeycloakError,
    ROLE_HIERARCHY,
)
from celine.policies.cli.keycloak.models import KeycloakConfig
from celine.policies.cli.keycloak.platform import require_platform
from celine.policies.cli.keycloak.registry import (
    RegistryError,
    fetch_rec_documents,
    issuer_url,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings, SyncUsersSettings
from celine.policies.cli.keycloak.commands._utils import (
    configure_logging,
    build_settings,
    load_rec_community_info,
    load_rec_operators,
    load_rec_participants,
    participant_username,
    read_rec_documents,
    require_realm_claim_scopes,
)
from celine.provisioning import OrganizationSpec, Provisioner
from celine.provisioning.invitation import INVITE_ACTIONS, EmailPolicy

logger = logging.getLogger(__name__)

MOCK_EMAIL_DOMAIN = "celine.localhost"


class _SourceError(Exception):
    """Neither source is usable, with what an operator has to supply named."""


@dataclass(frozen=True)
class CommunityPlan:
    """One community's worth of what this command provisions.

    The bundle carries all three together and they are reconciled together, so
    they travel together rather than as three parallel lists a caller has to
    keep in step.
    """

    community: dict
    participants: list[dict]
    operators: list[dict]

    @property
    def community_type(self) -> str:
        return self.community.get("type", "rec")


def _resolve_source(
    sync_settings: SyncUsersSettings,
    *,
    kc_settings: KeycloakSettings,
    from_registry: bool,
) -> tuple[list[dict], str]:
    """Fetch REC bundles from whichever source this run selected.

    Returns the parsed documents and a short name for where they came from, for
    the banner and for every error message below — "which source" is the first
    thing anybody reading a surprising plan needs to know, and the value alone
    does not say it.

    **The file path survives and is not deprecated.** Bootstrap runs before the
    registry holds anything, and an offline or air-gapped run is real. What the
    registry adds is that a run reconciles what is *true* rather than what was
    exported; both are correct answers to different questions.
    """
    if from_registry and sync_settings.rec_yaml:
        raise _SourceError(
            f"--from-registry and a REC YAML path ({sync_settings.rec_yaml}) are "
            f"mutually exclusive. Drop one: the registry would have been used."
        )

    if from_registry:
        if not sync_settings.registry_url:
            raise _SourceError(
                "--from-registry needs a registry URL. Pass --registry-url or set "
                "CELINE_SYNC_USERS_REGISTRY_URL."
            )
        secret = sync_settings.resolve_registry_secret(kc_settings.secrets_file)
        if not secret:
            raise _SourceError(
                f"No secret for registry client "
                f"'{sync_settings.registry_client_id}'. Pass "
                f"--registry-client-secret, set "
                f"CELINE_SYNC_USERS_REGISTRY_CLIENT_SECRET, or run "
                f"'celine-policies keycloak sync' so the client's secret is "
                f"recorded in {kc_settings.secrets_file}."
            )
        issuer = issuer_url(kc_settings.base_url, kc_settings.realm)
        try:
            documents = asyncio.run(
                fetch_rec_documents(
                    registry_url=sync_settings.registry_url,
                    issuer=issuer,
                    client_id=sync_settings.registry_client_id,
                    client_secret=secret,
                    community_keys=list(sync_settings.communities) or None,
                    timeout=kc_settings.timeout,
                )
            )
        except RegistryError as e:
            raise _SourceError(str(e)) from e
        return documents, f"registry {sync_settings.registry_url}"

    resolved_yaml = sync_settings.rec_yaml
    if resolved_yaml is None:
        raise _SourceError(
            "REC source required. Pass a YAML path (or set "
            "CELINE_SYNC_USERS_REC_YAML), or pass --from-registry with "
            "--registry-url to read the live registry."
        )
    if not resolved_yaml.exists():
        raise _SourceError(f"file not found: {resolved_yaml}")

    try:
        documents = read_rec_documents(resolved_yaml)
        if sync_settings.communities:
            documents = _narrow_to_communities(
                documents, list(sync_settings.communities), source=str(resolved_yaml)
            )
    except (ValueError, OSError, yaml.YAMLError) as e:
        raise _SourceError(str(e)) from e
    return documents, str(resolved_yaml)


def _narrow_to_communities(
    documents: list[dict], keys: list[str], *, source: str
) -> list[dict]:
    """Keep only the named communities, refusing a name the source does not hold.

    Silently ignoring an unknown key is the failure that costs the most here: a
    typo in a scheduled `--community` would reconcile nothing and report
    success, so the REC drifts and the run that was supposed to catch it is the
    thing hiding it. The registry path gets this for free — the export answers
    404 — and the file path has to do it itself.
    """
    wanted = set(keys)
    kept = [
        doc
        for doc in documents
        if (doc.get("community") or {}).get("id") in wanted
    ]
    found = {(doc.get("community") or {}).get("id") for doc in kept}
    missing = sorted(wanted - found)
    if missing:
        raise ValueError(
            f"{source} holds no community named {', '.join(missing)}"
        )
    return kept


def _load_communities(documents: list[dict], *, source: str) -> list[CommunityPlan]:
    """Turn parsed bundles into per-community plans.

    This is the seam the whole source switch rests on: **nothing below here can
    tell which source the documents came from.** A file and `GET /admin/export`
    produce the same bytes, so they produce the same plans, and the provisioning
    below is reached by one path rather than two.
    """
    plans = []
    for index, doc in enumerate(documents):
        where = source if len(documents) == 1 else f"{source} (document {index + 1})"
        plans.append(
            CommunityPlan(
                community=load_rec_community_info(doc, source=where),
                participants=load_rec_participants(doc),
                operators=load_rec_operators(doc),
            )
        )

    aliases = [p.community["id"] for p in plans]
    duplicates = sorted({a for a in aliases if aliases.count(a) > 1})
    if duplicates:
        # Two documents naming one community would provision it twice and, worse,
        # make the second pass's member list the one that stands. The registry
        # cannot emit this — `key` is unique — so it means a hand-assembled file.
        raise ValueError(
            f"{source} declares {', '.join(duplicates)} more than once"
        )
    return plans


def _mock_email(username: str) -> str:
    """A dev-convenience email for `--mock`, which must not double an address.

    The username used to be derived from the member key, so appending a domain
    always produced something well formed. Now it is the registry's `user_id` —
    an opaque handle whose shape this command does not get to assume — and
    `../onboarding` sets it to the same string it used as the address, so
    `f"{username}@{domain}"` would make
    `a.person@example.org@celine.localhost`: something Keycloak accepts and
    nobody can receive mail at.

    **The test is on the string, not on what the string means.** A value already
    containing `@` cannot have a domain appended to it, whatever it is; that is
    all this checks, and it deliberately does not try to decide whether the
    username "is an email".
    """
    if "@" in username:
        return username
    return f"{username}@{MOCK_EMAIL_DOMAIN}"


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
                "Realm group path to also assign every participant (repeatable), "
                "e.g. /admins. Default: none — participants get their org-level "
                "group only.  [env: CELINE_SYNC_USERS_GROUPS]"
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
    admin_groups: Annotated[
        bool,
        typer.Option(
            "--admin-groups/--no-admin-groups",
            help=(
                "Also add participants to the groups clients.yaml declares under "
                "admin_permissions, so the service account granted over them can "
                "find what it administers. Default: true."
            ),
        ),
    ] = True,
    secrets_file: Annotated[
        Optional[Path],
        typer.Option("--secrets-file", "-s", help="Path to secrets file for auth"),
    ] = None,
    clients_config: Annotated[
        Path,
        typer.Option(
            "--clients-config",
            "-c",
            help="Path to clients YAML (admin_permissions groups participants are added to)",
        ),
    ] = Path("./clients.yaml"),
    # Reading the live registry instead of a file
    from_registry: Annotated[
        bool,
        typer.Option(
            "--from-registry",
            help=(
                "Read REC definitions from the live rec-registry rather than a "
                "file, so members onboarded since the last export are included."
            ),
        ),
    ] = False,
    registry_url: Annotated[
        Optional[str],
        typer.Option(
            "--registry-url",
            help=(
                "rec-registry base URL; implies --from-registry  "
                "[env: CELINE_SYNC_USERS_REGISTRY_URL]"
            ),
        ),
    ] = None,
    registry_client_id: Annotated[
        Optional[str],
        typer.Option(
            "--registry-client-id",
            help=(
                "Keycloak client to read the registry as. Default: celine-cli  "
                "[env: CELINE_SYNC_USERS_REGISTRY_CLIENT_ID]"
            ),
        ),
    ] = None,
    registry_client_secret: Annotated[
        Optional[str],
        typer.Option(
            "--registry-client-secret",
            help=(
                "Secret for that client; falls back to the secrets file  "
                "[env: CELINE_SYNC_USERS_REGISTRY_CLIENT_SECRET]"
            ),
        ),
    ] = None,
    communities: Annotated[
        Optional[list[str]],
        typer.Option(
            "--community",
            help=(
                "Community key to reconcile (repeatable). Omit to reconcile "
                "every community the source holds.  "
                "[env: CELINE_SYNC_USERS_COMMUNITIES]"
            ),
        ),
    ] = None,
    invite: Annotated[
        bool,
        typer.Option(
            "--invite",
            help=(
                "Create new accounts with no password and have Keycloak email each "
                "one an invitation to set their own. Only accounts created in this "
                "run are invited, never existing ones. Follows the provisioning "
                "service's settings: CELINE_PROVISIONING_EMAIL_MODE (default dev: "
                "only EMAIL_DEV_RECIPIENTS are emailed), "
                "CELINE_PROVISIONING_INVITE_REDIRECT_URI and "
                "CELINE_PROVISIONING_INVITE_LIFESPAN. Not with --password or "
                "--reset-password."
            ),
        ),
    ] = False,
    check: Annotated[
        bool,
        typer.Option(
            "--check",
            help=(
                "Reconcile nothing; report members whose Keycloak state does not "
                "match the source and exit non-zero if any do. For a schedule."
            ),
        ),
    ] = False,
) -> None:
    """Ensure Keycloak users exist for every participant in a REC registry YAML.

    Reads the REC YAML, checks each participant's user_id against Keycloak,
    and creates any missing users with a temporary password (forced reset on
    first login), in their REC organization and its `viewers` org group. No
    realm group is assigned unless `--group` names one.

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
        celine-policies keycloak sync-users example-rec.yaml --dry-run

        # admin-user auth
        celine-policies keycloak sync-users example-rec.yaml \\
            --admin-user admin --admin-password admin

        # an explicit realm group, fixed password for a demo handout
        celine-policies keycloak sync-users example-rec.yaml \\
            --group /community-gl \\
            --temp-password "Demo@2025"

        # fully env-driven (CI/CD, docker-compose)
        CELINE_KEYCLOAK_BASE_URL=https://kc.example.com \\
        CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET=xxx \\
        CELINE_SYNC_USERS_REC_YAML=example-rec.yaml \\
        CELINE_SYNC_USERS_GROUPS="/community-gl" \\
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
        registry_url=registry_url,
        registry_client_id=registry_client_id,
        registry_client_secret=registry_client_secret,
        communities=communities,
    )

    configure_logging(sync_settings.verbose)

    if invite and (sync_settings.temp_password or reset_password):
        # An invitation exists so that nobody is handed a password. Creating one
        # anyway and then inviting the person to replace it would be both.
        typer.secho(
            "Error: --invite creates accounts without a password; it cannot be "
            "combined with --password/--temp-password or --reset-password.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)

    kc_settings = build_settings(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
        secrets_file=secrets_file,
    )

    try:
        documents, source = _resolve_source(
            sync_settings,
            kc_settings=kc_settings,
            from_registry=from_registry or bool(sync_settings.registry_url),
        )
    except _SourceError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    try:
        communities_to_sync = _load_communities(documents, source=source)
    except Exception as e:
        typer.secho(f"Error reading {source}: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    # Groups some client's service account is declared to administer. A
    # participant this command creates outside them is invisible to that
    # service: it attempts a create, gets 409, scans the group and does not find
    # the account. Read from the same declaration `sync` grants from, so the two
    # cannot name different groups.
    admin_group_owners: dict[str, list[str]] = {}
    if clients_config.exists():
        try:
            kc_config = KeycloakConfig.from_yaml(clients_config)
            if admin_groups:
                admin_group_owners = kc_config.admin_permission_group_paths()
        except Exception as e:
            typer.secho(
                f"Warning: could not load clients config {clients_config}: {e}",
                fg=typer.colors.YELLOW,
                err=True,
            )

    total_participants = sum(len(c.participants) for c in communities_to_sync)
    typer.echo(f"Source   : {source} — {len(communities_to_sync)} community(ies)")
    typer.echo(f"Keycloak : {kc_settings.base_url}  realm={kc_settings.realm}")
    for plan in communities_to_sync:
        typer.echo(
            f"REC org  : {plan.community['id']} ({plan.community['name']}) "
            f"[type={plan.community_type}] — "
            f"{len(plan.participants)} participant(s)"
        )
        if plan.operators:
            typer.echo(
                f"DSO orgs : {', '.join(op['id'] for op in plan.operators)}"
            )
    typer.echo(f"Org groups: {' > '.join(ROLE_HIERARCHY)} (viewers assigned to members)")
    if sync_settings.groups:
        typer.echo(f"Extra groups: {', '.join(sync_settings.groups)}")
    if admin_group_owners:
        typer.echo(
            "Admin groups: "
            + ", ".join(
                f"{path} (declared by {', '.join(owners)})"
                for path, owners in admin_group_owners.items()
            )
        )
    invitations = _invitation_settings() if invite else None
    if not check:
        if invitations:
            typer.echo(
                f"Password : none — new accounts are invited "
                f"(email mode {invitations.policy.mode})"
            )
        else:
            typer.echo(
                f"Password : {'fixed' if sync_settings.temp_password else 'random per user'}"
            )
    if sync_settings.dry_run and not check:
        typer.secho("\n[DRY RUN] No changes will be applied.\n", fg=typer.colors.YELLOW)
    if check:
        typer.secho("\n[CHECK] Reporting only. Nothing is written.\n", fg=typer.colors.YELLOW)

    if not total_participants:
        typer.secho(
            f"No active members found in {source}.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(0)

    if check:
        try:
            findings = asyncio.run(
                _async_check(
                    kc_settings=kc_settings,
                    communities=communities_to_sync,
                    admin_group_paths=list(admin_group_owners),
                )
            )
        except KeycloakAuthError as e:
            typer.secho(f"Authentication failed: {e}", fg=typer.colors.RED, err=True)
            raise typer.Exit(1)
        except KeycloakError as e:
            typer.secho(f"Keycloak error: {e}", fg=typer.colors.RED, err=True)
            raise typer.Exit(1)

        typer.echo(f"\nChecked {total_participants} member(s).")
        if not findings:
            typer.secho("  No divergence.", fg=typer.colors.GREEN)
            return
        typer.secho(f"  Divergence: {len(findings)}", fg=typer.colors.RED)
        raise typer.Exit(1)

    try:
        created, skipped, errors = asyncio.run(
            _async_sync_users(
                kc_settings=kc_settings,
                sync_settings=sync_settings,
                communities=communities_to_sync,
                admin_group_paths=list(admin_group_owners),
                reset_password=reset_password,
                temporary=sync_settings.temporary,
                mock=mock,
                invitations=invitations,
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


@dataclass(frozen=True)
class InvitationSettings:
    """How `--invite` sends: the provisioning service's settings, read once.

    One source for both writers, so `sync-users` and the service cannot disagree
    about who may be emailed or how long a link lasts.
    """

    policy: EmailPolicy
    lifespan: int
    client_id: str
    redirect_uri: str | None


def _invitation_settings() -> InvitationSettings:
    # Imported here: the settings module pulls the SDK's OIDC settings, which no
    # other sync-users path needs.
    from celine.provisioning.config import ProvisioningSettings

    settings = ProvisioningSettings()
    return InvitationSettings(
        policy=settings.email_policy,
        lifespan=settings.invite_lifespan,
        client_id=settings.invite_client_id,
        redirect_uri=settings.invite_redirect_uri,
    )


async def _async_sync_users(
    kc_settings: "KeycloakSettings",
    sync_settings: "SyncUsersSettings",
    communities: list[CommunityPlan],
    admin_group_paths: list[str] | None = None,
    reset_password: bool = False,
    temporary: bool = True,
    mock: bool = False,
    invitations: InvitationSettings | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """Reconcile Keycloak against every community this run was given.

    Two halves, and the split is the point: the realm-level scaffolding runs
    **once**, and the community-level work runs once per community. Before this
    was split there was only one community per run, so the two were interleaved
    and the distinction did not exist; reconciling every REC in one pass is what
    makes it matter. The realm half writes nothing any more: it checks the
    platform and clients levels this command depends on, and resolves groups.

    `admin_group_paths` are the groups `clients.yaml` declares a service account
    may administer. Every participant is added to them whether the account was
    just created or already existed, which is what makes a re-run the backfill
    for accounts created before this behaviour existed.

    Returns (created, skipped, errors) aggregated across communities.
    """
    created: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []

    async with KeycloakAdminClient(kc_settings) as kc:
        await kc.authenticate()

        extra_group_ids = await _ensure_realm_scaffold(
            kc,
            kc_settings=kc_settings,
            sync_settings=sync_settings,
            admin_group_paths=admin_group_paths,
        )

        for plan in communities:
            if len(communities) > 1:
                typer.echo(f"\n{plan.community['id']}:")
            c, s, e = await _sync_community(
                kc,
                plan=plan,
                sync_settings=sync_settings,
                extra_group_ids=extra_group_ids,
                admin_group_paths=admin_group_paths,
                reset_password=reset_password,
                temporary=temporary,
                mock=mock,
                invitations=invitations,
            )
            created.extend(c)
            skipped.extend(s)
            errors.extend(e)

    return created, skipped, errors


async def _ensure_realm_scaffold(
    kc: "KeycloakAdminClient",
    *,
    kc_settings: "KeycloakSettings",
    sync_settings: "SyncUsersSettings",
    admin_group_paths: list[str] | None,
) -> dict[str, str]:
    """Everything that is true of the realm rather than of one community.

    Returns the realm group paths every participant is added to, resolved to
    ids. Resolution happens here — before any user is touched — so a run does
    not stop half way leaving some participants filed and some not.

    Nothing here writes the realm. Organizations are platform level
    (`bootstrap`) and the claim scopes clients level (`sync`): both are checked,
    in a dry run too, and a realm without them is refused with the command to run.
    """
    await require_platform(kc, organizations=True)
    await require_realm_claim_scopes(kc)

    # --- Explicit realm groups from --group (fail fast if missing) ----------
    extra_group_ids: dict[str, str] = {}
    for path in sync_settings.groups:
        group = await kc.get_group_by_path(path)
        if not group:
            raise KeycloakError(
                f"Group '{path}' not found in realm '{kc_settings.realm}'. "
                f"Create it first or remove it from --group."
            )
        extra_group_ids[path] = group["id"]
        logger.debug("Resolved group %s -> %s", path, group["id"])

    # --- Declared admin-permission groups (fail fast if missing) ------------
    # `sync` creates these when it grants the permission, and it owns realm
    # structure — so a missing one means the realm has not been synced from
    # the declaration this command just read, and creating it here would
    # paper over that. Resolved before any user is touched, like --group.
    for path in admin_group_paths or []:
        group = await kc.get_group_by_path(path)
        if not group:
            raise KeycloakError(
                f"Group '{path}' not found in realm '{kc_settings.realm}'. "
                f"It is declared under admin_permissions in the clients config; "
                f"run 'celine-policies keycloak sync' to create it, or pass "
                f"--no-admin-groups."
            )
        extra_group_ids[path] = group["id"]
        logger.debug("Resolved admin-permission group %s -> %s", path, group["id"])

    return extra_group_ids


async def _sync_community(
    kc: "KeycloakAdminClient",
    *,
    plan: CommunityPlan,
    sync_settings: "SyncUsersSettings",
    extra_group_ids: dict[str, str],
    admin_group_paths: list[str] | None = None,
    reset_password: bool = False,
    temporary: bool = True,
    mock: bool = False,
    invitations: InvitationSettings | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """Ensure one community's organization, its groups and its members.

    With `invitations`, an account **created in this run** gets no password and
    is sent an invitation; an account that already existed is never invited,
    because a reconcile that invited everyone without a password on every run
    would spam whoever has not acted on their email yet.

    Returns (created, skipped, errors) for this community alone.
    """
    created: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []

    provisioner = Provisioner(kc)
    community = plan.community
    operators = plan.operators

    if not sync_settings.dry_run:
        # The organizations, their org roles and their org groups are
        # `celine.provisioning`'s. This command decides *who* should exist —
        # from a file or from the registry — and the package makes it so; the
        # service in front of it makes the identical calls, which is what keeps
        # one writer rather than two implementations that agree today.
        outcome = await provisioner.ensure_community(
            OrganizationSpec(
                alias=community["id"],
                name=community["name"],
                description=community.get("description", ""),
                type=plan.community_type,
            ),
            [
                OrganizationSpec(
                    alias=op["id"],
                    name=op["name"],
                    description=op.get("contact") or "",
                    type="dso",
                )
                for op in operators
            ],
        )

        for dso in outcome.operators:
            if dso.created:
                typer.secho(
                    f"  + DSO org '{dso.alias}' created ({dso.org_id})",
                    fg=typer.colors.GREEN,
                )
            else:
                logger.debug("DSO org '%s' already exists (%s)", dso.alias, dso.org_id)
            for grp_name in dso.groups_created:
                typer.secho(
                    f"  + DSO org group '{grp_name}' created", fg=typer.colors.GREEN
                )

        rec = outcome.community
        if rec.created:
            typer.secho(
                f"  + REC org '{rec.alias}' created ({rec.org_id})",
                fg=typer.colors.GREEN,
            )
        else:
            logger.debug("REC org '%s' already exists (%s)", rec.alias, rec.org_id)
        for grp_name in rec.groups_created:
            typer.secho(f"  + org group '{grp_name}' created", fg=typer.colors.GREEN)

        org_id = outcome.org_id
        member_grp_id = outcome.member_group_id
    else:
        # Dry-run: report orgs that would be provisioned
        for op in operators:
            existing_dso = await kc.get_organization_by_alias(op["id"])
            if existing_dso:
                typer.echo(f"  ✓ DSO '{op['id']}' — already exists ({existing_dso['id']})")
            else:
                typer.secho(
                    f"  ~ DSO '{op['id']}' — would create organization",
                    fg=typer.colors.YELLOW,
                )
        existing_rec = await kc.get_organization_by_alias(community["id"])
        if existing_rec:
            typer.echo(f"  ✓ REC '{community['id']}' — already exists ({existing_rec['id']})")
        else:
            typer.secho(
                f"  ~ REC '{community['id']}' — would create organization",
                fg=typer.colors.YELLOW,
            )
        org_id = None
        member_grp_id = None

    # --- Per-participant sync ---------------------------------------------
    admin_hint = (
        f" groups={', '.join(admin_group_paths)}" if admin_group_paths else ""
    )

    for p in plan.participants:
        key = p["key"]
        username = participant_username(p)

        pwd = None if invitations else sync_settings.generate_password()

        if sync_settings.dry_run:
            existing = await kc.get_user_by_username(username)
            member_group_name = "viewers"
            group_hint = f" org-group={member_group_name}" if member_group_name else ""
            if existing:
                typer.echo(
                    f"  ✓ {key} — exists as '{existing.get('username')}'"
                    f" (org: {community['id']}{group_hint}){admin_hint}"
                )
                skipped.append(username)
            else:
                typer.secho(
                    f"  ~ {key} username='{username}'"
                    f" org={community['id']}{group_hint}{admin_hint}"
                    + (" [would invite]" if invitations else ""),
                    fg=typer.colors.YELLOW,
                )
                created.append(username)
            continue

        try:
            assert org_id is not None  # guaranteed in live (non-dry-run) path

            # `--mock` is the only thing that puts an address on an account this
            # command creates, and it is a dev convenience: the registry holds
            # no email column, so a participant provisioned from it has none.
            email = _mock_email(username) if mock else None
            name = username if mock else None

            result = await provisioner.ensure_participant(
                username=username,
                org_id=org_id,
                member_group_id=member_grp_id,
                realm_group_ids=extra_group_ids,
                email=email,
                first_name=name,
                last_name=name,
                email_verified=mock,
                password=pwd,
                temporary=temporary,
                reset_password=reset_password,
            )

            if not result.created:
                if result.password_set:
                    typer.echo(
                        f"  ✓ {key} — already exists ({result.keycloak_id}), password reset"
                        + (" [org joined]" if result.org_joined else "")
                        + admin_hint
                    )
                else:
                    typer.echo(
                        f"  ✓ {key} — already exists ({result.keycloak_id})"
                        + (" [org joined]" if result.org_joined else "")
                        + admin_hint
                    )
                skipped.append(username)
                continue

            if invitations:
                outcome = await _invite_created(
                    provisioner,
                    invitations,
                    f"{community['id']}/{key}",
                    result.keycloak_id,
                    email,
                )
                credential = f"invitation={outcome}"
            else:
                credential = f"pwd='{pwd}'"
            typer.secho(
                f"  + {key} username='{username}' uuid={result.keycloak_id} {credential}"
                f" org={community['id']}{admin_hint}",
                fg=typer.colors.GREEN,
            )
            created.append(username)

        except Exception as e:
            msg = f"{key} ({username}): {e}"
            typer.secho(f"  ✗ {msg}", fg=typer.colors.RED)
            errors.append(msg)

    return created, skipped, errors


async def _invite_created(
    provisioner: Provisioner,
    invitations: InvitationSettings,
    who: str,
    keycloak_id: str,
    email: str | None,
) -> str:
    """Invite an account this run just created. Returns the outcome to print.

    The same decision the provisioning service makes for a created account:
    the dev list first, then the send. `no_address` is this command's own case —
    the registry holds no email, so outside `--mock` there is nobody to write to.
    """
    if not email:
        logger.warning("Not inviting %s: the account has no email address", who)
        return "no_address"
    if not invitations.policy.allows(email):
        invitations.policy.refuse(who)
        return "not_on_dev_list"
    await provisioner.send_actions_email(
        keycloak_id,
        INVITE_ACTIONS,
        lifespan=invitations.lifespan,
        client_id=invitations.client_id,
        redirect_uri=invitations.redirect_uri,
    )
    return "sent"


@dataclass(frozen=True)
class Divergence:
    """One member whose Keycloak state does not match the source.

    `kind` is what is wrong, not what to do about it: the repair for every one
    of these is the same run without `--check`, and naming the class is what
    lets a person tell "nobody onboarded has an account" from "one member drifted".
    """

    community: str
    key: str
    username: str
    kind: str
    detail: str = ""

    def __str__(self) -> str:
        suffix = f" — {self.detail}" if self.detail else ""
        return f"{self.community}/{self.key} ({self.username}): {self.kind}{suffix}"


async def _async_check(
    *,
    kc_settings: "KeycloakSettings",
    communities: list[CommunityPlan],
    admin_group_paths: list[str] | None = None,
) -> list[Divergence]:
    """Report what a sync would change, without changing it.

    **Why this exists.** The deployment's own health probes cannot see any of
    it: organization membership is not a liveness check, and the failure it
    produces is a person who logs in and cannot see their own community. On
    2026-09-11, 10 of 45 `/participants` members on demo3 were in their REC
    organization and nothing anywhere said so.

    **Which direction it checks, and why that is not the same as the plan's
    wording.** It walks the *source* — every active member the registry or file
    holds — and asks whether Keycloak agrees. The other direction, walking
    `/participants` and asking whether each member has a registry row, needs a
    paged scan of a flat group that ignores `search` (ADR-0004) and finds a
    different thing: an account with no member row is somebody onboarding
    created and the registry lost, which is that service's defect and not this
    command's to report.

    **It creates nothing, including organizations.** A REC the realm does not
    have is itself a finding, reported once for the community rather than once
    per member — otherwise one un-synced REC drowns every real per-member
    finding in its own member count.
    """
    findings: list[Divergence] = []

    async with KeycloakAdminClient(kc_settings) as kc:
        await kc.authenticate()

        for plan in communities:
            alias = plan.community["id"]
            typer.echo(f"\n{alias}:")

            org = await kc.get_organization_by_alias(alias)
            if not org:
                finding = Divergence(
                    community=alias,
                    key="-",
                    username="-",
                    kind="organization missing",
                    detail=f"{len(plan.participants)} member(s) cannot be placed",
                )
                typer.secho(f"  ✗ {finding}", fg=typer.colors.RED)
                findings.append(finding)
                continue

            for p in plan.participants:
                key = p["key"]
                username = participant_username(p)

                user = await kc.get_user_by_username(username)
                if not user:
                    finding = Divergence(alias, key, username, "no Keycloak account")
                    typer.secho(f"  ✗ {finding}", fg=typer.colors.RED)
                    findings.append(finding)
                    continue

                member_findings: list[Divergence] = []
                if not await kc.is_user_in_organization(org["id"], user["id"]):
                    member_findings.append(
                        Divergence(
                            alias,
                            key,
                            username,
                            "not in the REC organization",
                            "no `organization` claim, so no org-scoped policy resolves them",
                        )
                    )

                if admin_group_paths:
                    paths = {g.get("path") for g in await kc.get_user_groups(user["id"])}
                    for declared in admin_group_paths:
                        if declared not in paths:
                            member_findings.append(
                                Divergence(
                                    alias,
                                    key,
                                    username,
                                    f"not in {declared}",
                                    "invisible to the service account granted over it",
                                )
                            )

                for finding in member_findings:
                    typer.secho(f"  ✗ {finding}", fg=typer.colors.RED)
                findings.extend(member_findings)

                if not member_findings:
                    typer.echo(f"  ✓ {key} ({username})")

    return findings
