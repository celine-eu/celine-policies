"""Settings for the provisioning service.

Three groups, and the split matters:

- **`oidc`** — how an inbound token is verified. Every other celine service has
  the same block and reads it the same way.
- **`keycloak`** — the credential this service presents *outbound*, as
  `svc-provisioning`. Realm-wide administration, which is why the whole of
  `plans/provisioning-is-a-service-and-it-is-the-only-keycloak-writer.md` rests
  on there being no route to this service from outside the network.
- **`registry_*`** — where `POST /reconcile/{community}` reads a community from.

**The service cannot bootstrap the realm it authenticates against.** `keycloak
bootstrap` and `keycloak sync` create the client whose credential is configured
here, so they run first. The compose dependency says so; nothing in this process
can.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from celine.sdk.settings.models import OidcSettings

#: Scope authorising the upsert and the two lifecycle calls.
SCOPE_PARTICIPANTS_WRITE = "provisioning.participants.write"

#: Scope authorising a community sweep.
SCOPE_RECONCILE = "provisioning.reconcile"

#: `{service}.admin` satisfies every scope of that service — the admin-override
#: rule `clients.yaml` documents and every other celine service honours.
SCOPE_ADMIN = "provisioning.admin"


class ProvisioningSettings(BaseSettings):
    """What the provisioning service needs to run."""

    model_config = SettingsConfigDict(env_prefix="CELINE_PROVISIONING_", extra="ignore")

    oidc: OidcSettings = OidcSettings()

    # Where `POST /reconcile/{community}` reads from. Absent is legal and the
    # route then refuses rather than the process failing to start: the upsert
    # and the lifecycle calls need no registry at all, and a deployment that
    # only onboards should not be held up by a reconcile it never calls.
    registry_url: str | None = Field(
        default=None,
        description="rec-registry base URL for POST /reconcile/{community}",
    )
    registry_client_id: str = Field(
        default="svc-provisioning",
        description="Client id this service presents to the registry",
    )
    registry_client_secret: str | None = Field(
        default=None,
        description="Client secret for the registry credential",
    )

    log_level: str = Field(default="INFO", description="Logging level")
