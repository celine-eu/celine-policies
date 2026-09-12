"""Shared utilities for Keycloak CLI commands."""

from __future__ import annotations

import logging

import yaml
from pathlib import Path

from celine.governance import validate_owners

from celine.policies.cli.keycloak.settings import (
    KeycloakSettings,
    realm_is_set_in_environment,
)

# The bundle-reading half moved to `celine.provisioning.bundle`, beside the
# provisioning it feeds: the service reconciling a community reads the same
# bundle this command does, and a second parser is how the two come to disagree.
# Re-exported here because every `keycloak` command imports them from this
# module, and moving code is not a reason to move every import with it.
from celine.provisioning.bundle import (  # noqa: F401
    ACTIVE_MEMBER_STATUS,
    derive_username,
    load_rec_community_info,
    load_rec_operators,
    load_rec_participants,
    participant_username,
)


def configure_logging(verbose: bool) -> None:
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


def build_settings(
    base_url: str | None,
    realm: str | None,
    admin_user: str | None,
    admin_password: str | None,
    admin_client_id: str | None,
    admin_client_secret: str | None,
    secrets_file: Path | None = None,
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

    # Propagate explicit secrets_file override into settings so all
    # downstream calls (with_auto_secret, bootstrap write) use the same path
    if secrets_file:
        settings = settings.with_overrides(secrets_file=secrets_file)

    # Only auto-load client secret when admin user credentials were not explicitly
    # provided. If --admin-user/--admin-password are set, honour them as-is so
    # the caller can override a stale or missing client secret.
    if not (admin_user and admin_password):
        settings = settings.with_auto_secret()

    return settings


def resolve_realm(
    settings: KeycloakSettings,
    *,
    cli_realm: str | None,
    config_realm: str | None,
    config_source: str,
) -> tuple[KeycloakSettings, str]:
    """Decide which input aims this run, and name the one that won.

    `sync` is the only command with a third input for the realm — `realm:` in the
    declaration it is about to apply — and that input is committed and shared,
    while `CELINE_KEYCLOAK_REALM` is how one particular run is aimed. So the
    declaration supplies a default for a run nobody aimed, and nothing more:

        --realm  >  CELINE_KEYCLOAK_REALM  >  the declaration  >  the default

    which is the order every other command already has, with the declaration
    added at the bottom. It previously sat above the environment variable,
    because the test for "not aimed" was the CLI parameter alone and
    `build_settings` had already folded the environment into `settings`.

    Returns the settings to use and a short name for the input that supplied the
    realm, for the banner: the value alone does not say which input won, and that
    is the whole reason this was hard to see.
    """
    if cli_realm:
        return settings, "--realm"
    if realm_is_set_in_environment():
        return settings, "CELINE_KEYCLOAK_REALM"
    if config_realm:
        return settings.with_overrides(realm=config_realm), config_source
    return settings, "the default"


def read_rec_documents(rec_yaml: Path) -> list[dict]:
    """Parse a REC bundle file into one document per community.

    `safe_load_all` rather than `safe_load`: the registry's export is a
    multidocument stream whenever it covers more than one community, and a file
    somebody saved from it is the same bytes. A single-community file yields a
    one-element list, so the caller has one shape to handle either way.
    """
    docs = [doc for doc in yaml.safe_load_all(rec_yaml.read_text()) if doc]
    if not docs:
        raise ValueError(f"{rec_yaml} contains no YAML document")
    return docs


def load_owners(owner_yamls: list[Path]) -> list[dict]:
    """Load and merge owner registries from one or more YAML files.

    Later files shadow earlier entries on id collision, allowing local
    overrides to extend or replace entries from the base owners.yaml.

    Returns a list of owner dicts. Entries without an 'id' are skipped.

    Each file is checked against ``owners.schema.json`` before it is merged.
    This command provisions real Keycloak organizations, and the failure it
    prevents is a quiet one: a mistyped key is not an error anywhere — the
    schema was published but never executed, and the loop below skips an entry
    it cannot identify with a log line — so the registry loads, the run reports
    success, and one organization is simply missing. That surfaces later as an
    authorization failure with nothing to connect it to.

    Deliberately not merged through ``celine.governance.OwnersRegistry``: this
    stays on raw dicts because the shadowing merge across several files is not
    something the canonical single-file loader expresses, and because the
    Keycloak payloads below are built from the YAML shape directly.
    """
    logger = logging.getLogger(__name__)
    merged: dict[str, dict] = {}
    for path in owner_yamls:
        raw = yaml.safe_load(path.read_text())
        validate_owners(raw, source=str(path))
        for entry in raw.get("owners", []):
            owner_id = entry.get("id")
            if not owner_id:
                logger.warning("Owner entry without id in %s — skipping", path)
                continue
            if owner_id in merged:
                logger.debug("Owner '%s' shadowed by entry from %s", owner_id, path)
            merged[owner_id] = entry
    return list(merged.values())


