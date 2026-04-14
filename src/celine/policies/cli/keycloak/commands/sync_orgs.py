"""keycloak sync-orgs command.

Usage:
    celine-policies keycloak sync-orgs [owners_yaml ...]
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
from celine.policies.cli.keycloak.commands._utils import (
    configure_logging,
    build_settings,
    load_owners,
)

logger = logging.getLogger(__name__)


def sync_orgs(
    # Positional — one or more owners YAML files
    owners_yamls: Annotated[
        Optional[list[Path]],
        typer.Argument(
            help="Path(s) to owners YAML file(s)  [env: CELINE_SYNC_ORGS_OWNERS_YAML]"
        ),
    ] = None,
    # Keycloak connection
    base_url: Annotated[
        Optional[str],
        typer.Option("--base-url", "-u", help="Keycloak base URL  [env: CELINE_KEYCLOAK_BASE_URL]"),
    ] = None,
    realm: Annotated[
        Optional[str],
        typer.Option("--realm", "-r", help="Target realm  [env: CELINE_KEYCLOAK_REALM]"),
    ] = None,
    admin_user: Annotated[
        Optional[str],
        typer.Option("--admin-user", help="Admin username  [env: CELINE_KEYCLOAK_ADMIN_USER]"),
    ] = None,
    admin_password: Annotated[
        Optional[str],
        typer.Option("--admin-password", help="Admin password  [env: CELINE_KEYCLOAK_ADMIN_PASSWORD]"),
    ] = None,
    admin_client_id: Annotated[
        Optional[str],
        typer.Option("--admin-client-id", help="Admin client ID  [env: CELINE_KEYCLOAK_ADMIN_CLIENT_ID]"),
    ] = None,
    admin_client_secret: Annotated[
        Optional[str],
        typer.Option("--admin-client-secret", help="Admin client secret  [env: CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET]"),
    ] = None,
    clients_config: Annotated[
        Path,
        typer.Option(
            "--clients-config", "-c",
            help="Path to clients YAML (oauth2_proxy_client field used for org scope assignment)",
        ),
    ] = Path("./clients.yaml"),
    secrets_file: Annotated[
        Optional[Path],
        typer.Option("--secrets-file", "-s", help="Path to secrets file for auth"),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", "-n", help="Show planned changes without applying"),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose output"),
    ] = False,
) -> None:
    """Ensure Keycloak organizations exist for every owner entry with organization.create=true.

    Reads one or more owners YAML files (later files shadow earlier entries on
    id collision), filters to entries where organization.create is true, and
    idempotently provisions the corresponding Keycloak organization with:

      - organizations feature enabled on the realm
      - organization created (alias=id, name=name, attributes.type=[organization.role])
      - any extra key/value pairs from organization.attributes set on the KC org
      - 'organization' scope set as default on the oauth2_proxy client

    This command is idempotent — safe to run multiple times.

    Examples:
        # base + local overlay
        celine-policies keycloak sync-orgs owners.yaml owners.local.yaml

        # dry run to preview
        celine-policies keycloak sync-orgs owners.local.yaml --dry-run

        # env-driven (CI/CD)
        CELINE_SYNC_ORGS_OWNERS_YAML="owners.yaml owners.local.yaml" \\
        celine-policies keycloak sync-orgs
    """
    configure_logging(verbose)

    # Resolve owners YAML paths — argument > env var
    resolved_yamls: list[Path] = []
    if owners_yamls:
        resolved_yamls = list(owners_yamls)
    else:
        env_val = _env_owners_yaml()
        if env_val:
            resolved_yamls = [Path(p) for p in env_val.split()]

    if not resolved_yamls:
        typer.secho(
            "Error: at least one owners YAML path required. "
            "Pass as argument or set CELINE_SYNC_ORGS_OWNERS_YAML.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)

    for path in resolved_yamls:
        if not path.exists():
            typer.secho(f"Error: file not found: {path}", fg=typer.colors.RED, err=True)
            raise typer.Exit(1)

    try:
        owners = load_owners(resolved_yamls)
    except Exception as e:
        typer.secho(f"Error reading owners YAML: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    org_owners = [o for o in owners if o.get("organization", {}).get("create")]
    if not org_owners:
        typer.secho("No owners found in YAML — nothing to sync.", fg=typer.colors.YELLOW)
        raise typer.Exit(0)

    kc_settings = build_settings(
        base_url=base_url,
        realm=realm,
        admin_user=admin_user,
        admin_password=admin_password,
        admin_client_id=admin_client_id,
        admin_client_secret=admin_client_secret,
        secrets_file=secrets_file,
    )

    oauth2_proxy_client: str | None = None
    if clients_config.exists():
        try:
            kc_config = KeycloakConfig.from_yaml(clients_config)
            oauth2_proxy_client = kc_config.oauth2_proxy_client
        except Exception as e:
            typer.secho(
                f"Warning: could not load clients config {clients_config}: {e}",
                fg=typer.colors.YELLOW,
                err=True,
            )

    typer.echo(f"Owners   : {', '.join(str(p) for p in resolved_yamls)}")
    typer.echo(f"Orgs     : {len(org_owners)} owner(s) with organization.create=true")
    typer.echo(f"Keycloak : {kc_settings.base_url}  realm={kc_settings.realm}")
    if dry_run:
        typer.secho("\n[DRY RUN] No changes will be applied.\n", fg=typer.colors.YELLOW)

    try:
        created, skipped, errors = asyncio.run(
            _async_sync_orgs(
                kc_settings=kc_settings,
                org_owners=org_owners,
                oauth2_proxy_client=oauth2_proxy_client,
                dry_run=dry_run,
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

    typer.echo("\nDone.")
    typer.secho(f"  Created : {len(created)}", fg=typer.colors.GREEN)
    typer.echo(f"  Skipped : {len(skipped)} (already exist)")
    if errors:
        typer.secho(f"  Errors  : {len(errors)}", fg=typer.colors.RED)
        for err in errors:
            typer.secho(f"    - {err}", fg=typer.colors.RED)
        raise typer.Exit(1)


def _env_owners_yaml() -> str | None:
    import os
    return os.environ.get("CELINE_SYNC_ORGS_OWNERS_YAML")


async def _async_sync_orgs(
    kc_settings: "KeycloakSettings",
    org_owners: list[dict],
    oauth2_proxy_client: str | None = None,
    dry_run: bool = False,
) -> tuple[list[str], list[str], list[str]]:
    """Idempotently provision KC organizations for owners that have a role.

    Returns (created, skipped, errors).
    """
    created: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []

    async with KeycloakAdminClient(kc_settings) as kc:
        await kc.authenticate()

        if dry_run:
            for owner in org_owners:
                alias = owner["id"]
                org_block = owner.get("organization", {})
                role = org_block.get("role") or "org"
                org = await kc.get_organization_by_alias(alias)
                if org:
                    typer.echo(f"  ✓ {alias} ({role}) — already exists ({org['id']})")
                    skipped.append(alias)
                else:
                    typer.secho(
                        f"  ~ {alias} ({role}) — would create organization",
                        fg=typer.colors.YELLOW,
                    )
                    created.append(alias)
            return created, skipped, errors

        # --- Realm-level setup (once, idempotent) ----------------------------
        enabled = await kc.ensure_organizations_enabled()
        if enabled:
            typer.echo("  ! Organizations enabled on realm")

        if oauth2_proxy_client:
            client = await kc.get_client_by_client_id(oauth2_proxy_client)
            if client:
                _, scope_changed = await kc.ensure_org_client_scope()
                if scope_changed:
                    typer.echo("  ! organization client scope provisioned")
                assigned = await kc.ensure_org_scope_on_client(client["id"])
                if assigned:
                    typer.echo(f"  ! organization scope assigned to client '{oauth2_proxy_client}'")
                aud_added = await kc.ensure_audience_mapper(client["id"], oauth2_proxy_client)
                if aud_added:
                    typer.echo(f"  ! audience mapper added to client '{oauth2_proxy_client}'")
            else:
                logger.warning(
                    "Client '%s' not found — skipping mapper setup",
                    oauth2_proxy_client,
                )

        # --- Per-owner sync --------------------------------------------------
        for owner in org_owners:
            alias = owner["id"]
            name = owner.get("name", alias)
            org_block = owner.get("organization", {})
            role = org_block.get("role") or "org"
            extra_attrs = org_block.get("attributes") or {}
            kc_attributes = {"type": [role], **{k: [v] for k, v in extra_attrs.items()}}

            try:
                org_id, org_created = await kc.ensure_organization(
                    alias=alias,
                    name=name,
                    description=owner.get("url", ""),
                    attributes=kc_attributes,
                )

                if org_created:
                    typer.secho(
                        f"  + {alias} ({role}) — created ({org_id})",
                        fg=typer.colors.GREEN,
                    )
                    created.append(alias)
                else:
                    typer.echo(f"  ✓ {alias} ({role}) — already exists ({org_id})")
                    skipped.append(alias)

            except Exception as e:
                msg = f"{alias}: {e}"
                typer.secho(f"  ✗ {msg}", fg=typer.colors.RED)
                errors.append(msg)

    return created, skipped, errors
