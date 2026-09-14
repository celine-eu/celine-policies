"""Settings for the provisioning service.

Three groups, and the split matters:

- **`oidc`** — how an inbound token is verified. Every other celine service has
  the same block and reads it the same way.
- **`keycloak`** — the credential this service presents *outbound*, as
  `svc-provisioning`. Realm-wide administration, which is why the whole of
  `plans/provisioning-is-a-service-and-it-is-the-only-keycloak-writer.md` rests
  on there being no route to this service from outside the network.
- **`registry_*`** — where `POST /reconcile/{community}` reads a community from.
- **`invite_*`, `reset_lifespan`, `email_*`** — how an invitation is sent, and to
  whom it may be sent. Keycloak sends the email; these decide the link and the
  recipient guard.

**The service cannot bootstrap the realm it authenticates against.** `keycloak
bootstrap` and `keycloak sync` create the client whose credential is configured
here, so they run first. The compose dependency says so; nothing in this process
can.
"""

from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from celine.provisioning.invitation import EmailMode, EmailPolicy, parse_recipients
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

    model_config = SettingsConfigDict(
        env_prefix="CELINE_PROVISIONING_", extra="ignore", populate_by_name=True
    )

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

    # -- invitations --------------------------------------------------------
    # The redirect is configuration and never comes from the caller. Keycloak
    # refuses one not registered on `invite_client_id` with `400 "Invalid
    # redirect uri."`, so a wrong value fails loudly on the first send.
    invite_redirect_uri: str | None = Field(
        default=None,
        description=(
            "Where the 'back to the application' link on the final page points "
            "(the webapp root). Unset: the link carries no redirect."
        ),
    )
    invite_client_id: str = Field(
        default="oauth2_proxy",
        description="Client the redirect URI is registered on",
    )
    invite_lifespan: int = Field(
        default=604800,
        gt=0,
        description="Lifespan in seconds of an invitation link (7 days)",
    )
    reset_lifespan: int = Field(
        default=3600,
        gt=0,
        description="Lifespan in seconds of an operator reset link (1 hour)",
    )
    invite_cooldown: int = Field(
        default=300,
        ge=0,
        description=(
            "Seconds after a successful send during which any further send to the "
            "same account is refused, by the route (429) or the upsert (cooldown). "
            "A failed send starts none. In memory, per replica: a double-click guard."
        ),
    )
    email_mode: EmailMode = Field(
        default="dev",
        description="'deliver' emails anyone; 'dev' only EMAIL_DEV_RECIPIENTS",
    )
    email_dev_recipients: str = Field(
        default="",
        validation_alias=AliasChoices(
            "CELINE_PROVISIONING_EMAIL_DEV_RECIPIENTS",
            "EMAIL_DEV_RECIPIENTS",
            "email_dev_recipients",
        ),
        description="Comma-separated addresses that may be emailed in 'dev' mode",
    )

    log_level: str = Field(default="INFO", description="Logging level")

    @property
    def email_policy(self) -> EmailPolicy:
        return EmailPolicy(
            mode=self.email_mode,
            dev_recipients=parse_recipients(self.email_dev_recipients),
        )
