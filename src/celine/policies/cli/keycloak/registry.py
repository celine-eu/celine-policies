"""Re-export of the registry reader, which now lives with the provisioning.

It moved to `celine.provisioning.registry` when the provisioning service was
built: the service's `POST /reconcile/{community}` fetches exactly what
`keycloak sync-users --from-registry` fetches, and two copies of a fetch is how
the two come to disagree about what a community is.

`keycloak sync-users` imports from here, so the module stays.
"""

from celine.provisioning.registry import (  # noqa: F401
    RegistryError,
    fetch_rec_documents,
    issuer_url,
)

__all__ = ["RegistryError", "fetch_rec_documents", "issuer_url"]
