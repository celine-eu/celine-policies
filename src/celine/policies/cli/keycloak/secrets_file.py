"""The one writer of `.client.secrets.yaml`.

The file is the store of the credentials this CLI authenticates with:
`KeycloakSettings.with_auto_secret` reads `celine-admin-cli` back out of it for any
run that passes no `--admin-user`, and `task keycloak:sync` relies on exactly that.

Two commands write it — `bootstrap` puts the admin client there, `sync` puts every
client it created or updated — so a writer that rewrites the file from scratch
deletes the credential the other one wrote. That is what happened: a sync that
changed anything dropped the admin secret, and the file afterwards looked plausible
rather than empty, which is why it survived so long.

So every write goes through `merge_secrets_file`. It merges by client id and leaves
untouched every entry it was not given.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

WARNING_COMMENT = (
    "# WARNING: This file contains sensitive credentials. DO NOT COMMIT.\n"
)

# `sync` used to write the warning as a YAML *key* while `bootstrap` wrote a real
# comment. Dropped on read and re-emitted as a comment, so a file written by the
# old sync converges on the first write rather than carrying both forever.
_LEGACY_WARNING_KEY = "# WARNING"


def read_secrets_file(path: Path) -> dict[str, Any]:
    """Return the file's contents, or an empty dict if it is absent or unreadable.

    Unreadable is deliberately not an error: the file holds credentials that can
    be re-fetched, and refusing to write over a corrupt one would strand the
    command that is trying to repair it.
    """
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text())
    except Exception as e:
        logger.warning("Could not parse %s (%s) — treating it as empty", path, e)
        return {}
    return data if isinstance(data, dict) else {}


def merge_secrets_file(
    path: Path,
    realm: str,
    clients: dict[str, dict[str, Any]],
) -> None:
    """Merge `clients` into the secrets file, leaving every other entry alone.

    `realm` is the realm the run actually wrote to, not the one its declaration
    names — see celine-policies#4, where those two came apart.

    **A realm change replaces the file rather than merging into it.** The file
    carries one `realm:` key and the reader looks clients up flat, so two realms'
    credentials are not representable in it: the same `client_id` is a different
    client with a different secret in each. Merging across the change would hand
    the next run a credential from the wrong realm, so the stale entries go and
    the caller is told.
    """
    existing = read_secrets_file(path)
    existing.pop(_LEGACY_WARNING_KEY, None)

    previous_realm = existing.get("realm")
    kept = existing.get("clients")
    if not isinstance(kept, dict):
        kept = {}
    if previous_realm and previous_realm != realm:
        logger.warning(
            "%s held credentials for realm %s — replacing them for realm %s",
            path,
            previous_realm,
            realm,
        )
        kept = {}

    data = dict(existing)
    data["generated_at"] = datetime.now(timezone.utc).isoformat()
    data["realm"] = realm
    data["clients"] = {**kept, **clients}

    path.write_text(
        WARNING_COMMENT
        + yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
    )
    logger.info("Wrote %d client(s) to: %s", len(clients), path)
