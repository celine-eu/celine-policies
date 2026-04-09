"""Shared utilities for Keycloak CLI commands."""

from __future__ import annotations

import logging

import yaml
from pathlib import Path

from celine.policies.cli.keycloak.settings import KeycloakSettings


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

    settings = settings.with_auto_secret()

    return settings


def load_rec_participants(rec_yaml: Path) -> list[dict]:
    """Extract participant records from a REC registry YAML.

    Returns a list of dicts with keys: user_id, key, name.
    Participants without a user_id are skipped with a warning.
    """
    logger = logging.getLogger(__name__)
    raw = yaml.safe_load(rec_yaml.read_text())
    # Support both "members" (new schema) and "participants" (legacy)
    participants_raw = raw.get("members") or raw.get("participants", {})

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


def load_rec_community_info(rec_yaml: Path) -> dict:
    """Extract community metadata from a REC registry YAML.

    Returns a dict with keys: id, name, description.
    Raises ValueError if community.id is missing.
    """
    raw = yaml.safe_load(rec_yaml.read_text())
    community = raw.get("community", {})
    rec_id = community.get("id")
    if not rec_id:
        raise ValueError(f"YAML {rec_yaml} is missing community.id")
    return {
        "id": rec_id,
        "name": community.get("name", rec_id),
        "description": community.get("description", ""),
    }


def derive_username(participant_key: str) -> str:
    """Stable Keycloak username from the participant key (e.g. 'gl-00001').

    Unique within the community, no PII, safe to hand out during demos.
    """
    return participant_key.lower()
