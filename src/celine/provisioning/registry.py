"""Reading REC definitions from the live rec-registry instead of from a file.

Provisioning reconciled a **file**, so whatever snapshot an operator exported was
what the realm was made to match. Members arrive at runtime now — `../onboarding`
writes one to the registry on every approval — so the file is a picture of the
community at export time and anybody onboarded since it was taken is invisible to
the sync.

**This is not a new contract.** `GET /admin/export` returns exactly the bundle YAML
the loaders in `bundle.py` already parse, and with no `community`
parameter it returns every community as a multidocument stream. So the whole of
the change is where the bytes come from; nothing below the loaders can tell.

## Why there is so little here

`celine-sdk` is already a dependency and already has both halves —
`RecRegistryAdminClient.export_communities` and `OidcClientCredentialsProvider`.
Writing an httpx call and a token cache here would be a second implementation of
a client the platform already generates from the registry's own OpenAPI document,
and it would drift from it.

## Why only one method is imported

The credential this carries is `celine-cli` by default, which holds
`rec-registry.admin` — and that scope satisfies every grant through the SDK's
admin override, including `rec-registry.import`, a replacement import that
deletes a community with every member in it, and `rec-registry.members.purge`.

That is wider than this command needs and was chosen knowingly (see the store's
`plans/the-registry-is-the-source-and-the-yaml-is-the-seed.md`). What keeps it
honest is below rather than in the realm: **`export_communities` is the only
registry method named in this repository.** Keep it that way, and keep the client
id configurable, so a client holding `rec-registry.export` alone can replace it
without a code change.
"""

from __future__ import annotations

import logging

import yaml

logger = logging.getLogger(__name__)


class RegistryError(RuntimeError):
    """The registry could not be read, with the inputs named.

    A bare 401 from the registry is the expected shape of a hostname mismatch —
    a token minted at one issuer and presented to a service validating against
    another — and "unauthorized" alone sends an operator to the wrong place. So
    every message this raises names the issuer it minted at, the URL it called
    and the client id it used.
    """


def issuer_url(keycloak_base_url: str, realm: str) -> str:
    """The OIDC issuer for a realm, which is what discovery is rooted at.

    The SDK appends `/.well-known/openid-configuration` to whatever it is given,
    so this is the realm URL and not the Keycloak base.

    **It must be the hostname the registry validates against.** The registry
    resolves a JWKS URI of its own; a token minted at `http://keycloak:8080` and
    presented to a service configured for `http://keycloak.celine.localhost` is
    rejected as unauthorized, with nothing in the message about hostnames.
    """
    return f"{keycloak_base_url.rstrip('/')}/realms/{realm}"


async def fetch_rec_documents(
    *,
    registry_url: str,
    issuer: str,
    client_id: str,
    client_secret: str,
    community_keys: list[str] | None = None,
    timeout: float = 30.0,
) -> list[dict]:
    """Fetch REC bundles from the registry, one parsed document per community.

    `community_keys` narrows the export; omit it and the registry returns every
    community it holds. That is what makes a scheduled reconcile possible
    without a list of REC slugs maintained somewhere else — the tenant list
    comes from the registry, in the same artefact as the members.

    Returns the same shape `read_rec_documents` returns for a file, which is the
    property the whole change rests on.
    """
    # Imported here rather than at module scope: `celine-sdk` pulls its
    # generated registry client and an httpx stack behind it, and every other
    # `keycloak` subcommand would pay for that import without ever reading a
    # registry.
    from celine.sdk.auth import OidcClientCredentialsProvider
    from celine.sdk.rec_registry import RecRegistryAdminClient

    provider = OidcClientCredentialsProvider(
        base_url=issuer,
        client_id=client_id,
        client_secret=client_secret,
        timeout=timeout,
    )
    client = RecRegistryAdminClient(
        base_url=registry_url.rstrip("/"),
        token_provider=provider,
        timeout=timeout,
    )

    logger.debug(
        "Exporting %s from %s as %s (issuer %s)",
        ", ".join(community_keys) if community_keys else "every community",
        registry_url,
        client_id,
        issuer,
    )
    try:
        text = await client.export_communities(community_keys or None)
    except Exception as e:
        raise RegistryError(
            f"Could not export from {registry_url} as '{client_id}' "
            f"(token issuer {issuer}): {e}. A 401 here usually means the issuer "
            f"is not the hostname the registry validates against, and a 403 "
            f"means '{client_id}' does not hold rec-registry.export."
        ) from e

    try:
        documents = [doc for doc in yaml.safe_load_all(text) if doc]
    except yaml.YAMLError as e:
        raise RegistryError(
            f"{registry_url} returned something that is not YAML: {e}"
        ) from e

    if not documents:
        raise RegistryError(
            f"{registry_url} exported no community"
            + (f" for {', '.join(community_keys)}" if community_keys else "")
            + ". An empty registry is the expected state before onboarding has "
            "approved anybody; seed it from a file instead."
        )
    return documents
