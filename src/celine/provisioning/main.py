"""The provisioning service's ASGI app.

**It cannot bootstrap the realm it authenticates against.** `keycloak bootstrap`
and `keycloak sync` create `svc-provisioning` and record its secret, so they run
before this process starts and stay CLI commands. `docker-compose.yaml` says so
with a dependency; there is nothing this app can do about it at startup beyond
failing to authenticate, which it will.

**There is deliberately no route beyond the four and `/health`.** The argument
that a service holding `manage-users` and `manage-realm` is safe rests entirely
on nothing outside the network reaching it — see ADR-0007. A route added here by
accident converts that credential into an internet-facing one, and the guard
that keeps it unreachable lives with the ingress configuration, not in this file.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from celine.policies.cli.keycloak.settings import KeycloakSettings
from celine.provisioning.config import ProvisioningSettings
from celine.provisioning.routes import get_service, get_settings, router
from celine.provisioning.service import ProvisioningService

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the provisioning application."""
    settings = ProvisioningSettings()
    keycloak_settings = KeycloakSettings()

    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    app = FastAPI(
        title="CELINE Provisioning Service",
        description=(
            "The only writer of participant accounts in the celine realm. "
            "Internal: no public route, and authorization by provisioning.* scopes."
        ),
        # 1.1.0: `…/password-reset` replaced by `…/invitation`, and the upsert
        # gained `locale`, `invite` and `invitation`. Bumped so the SDK's spec
        # snapshot is a new version rather than an overwrite in place.
        version="1.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # No CORS middleware, and that is not an omission. A browser never calls
    # this service: every caller is another service presenting a client
    # credential, so allowing cross-origin requests would only widen what can
    # reach a realm-wide admin credential.

    service = ProvisioningService(settings, keycloak_settings)

    app.state.settings = settings
    app.state.service = service
    app.dependency_overrides[get_settings] = lambda: app.state.settings
    app.dependency_overrides[get_service] = lambda: app.state.service

    app.include_router(router)

    @app.get("/health")
    async def health_check():
        """Liveness only.

        It deliberately does **not** authenticate against Keycloak. A health
        probe that reaches the realm turns a Keycloak restart into a cascade of
        restarted services, and this service's readiness to answer is not the
        same question as the realm's.
        """
        return {
            "status": "healthy",
            "keycloak": keycloak_settings.base_url,
            "realm": keycloak_settings.realm,
            "registry": settings.registry_url or "not configured",
        }

    logger.info(
        "Provisioning service ready — realm=%s registry=%s email_mode=%s",
        keycloak_settings.realm,
        settings.registry_url or "not configured",
        settings.email_mode,
    )
    if settings.email_mode == "dev":
        logger.warning(
            "Email mode is 'dev': invitations go only to %d address(es) on "
            "EMAIL_DEV_RECIPIENTS. Set CELINE_PROVISIONING_EMAIL_MODE=deliver "
            "to email participants.",
            len(settings.email_policy.dev_recipients),
        )
    if not settings.invite_redirect_uri:
        logger.warning(
            "CELINE_PROVISIONING_INVITE_REDIRECT_URI is unset: invitation links "
            "end on Keycloak's page with no link back to the application."
        )
    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_app(), host="0.0.0.0", port=8010)
