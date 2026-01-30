"""CELINE Policy Service - FastAPI Application."""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from celine.policies.audit import AuditLogger, configure_audit_logging
from celine.policies.auth import JWKSCache, JWTValidator
from celine.policies.config import Settings, settings as app_settings
from celine.policies.engine import CachedPolicyEngine, DecisionCache, PolicyEngine
from celine.policies.logs import configure_logging as configure_app_logging
from celine.policies.routes import (
    authorize_router,
    dataset_router,
    health_router,
    mqtt_router,
    pipeline_router,
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _policy_engine, _jwt_validator, _audit_logger

    settings = app_settings

    configure_app_logging()

    configure_audit_logging(
        log_level=settings.log_level,
        json_format=settings.environment != "development",
        service_name=settings.service_name,
    )

    logger.info("Starting CELINE Policy Service")

    engine = PolicyEngine(
        policies_dir=settings.policies_dir,
        data_dir=settings.data_dir,
    )
    engine.load()

    cache = DecisionCache(
        maxsize=settings.decision_cache_maxsize,
        ttl_seconds=settings.decision_cache_ttl_seconds,
    )
    _policy_engine = CachedPolicyEngine(
        engine=engine,
        cache=cache,
        cache_enabled=settings.decision_cache_enabled,
    )

    jwks_cache = JWKSCache(
        jwks_uri=settings.jwks_uri,
        ttl_seconds=settings.jwks_cache_ttl_seconds,
    )
    _jwt_validator = JWTValidator(
        jwks_cache=jwks_cache,
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        algorithms=settings.jwt_algorithms,
    )

    _audit_logger = AuditLogger(
        enabled=settings.audit_enabled,
        log_inputs=settings.audit_log_inputs,
    )

    logger.info("Service initialized")

    yield

    logger.info("Shutting down CELINE Policy Service")


def create_app(settings_override: Settings | None = None) -> FastAPI:
    settings = settings_override or app_settings

    app = FastAPI(
        title="CELINE Policy Service",
        description="Centralized authorization service for the CELINE platform",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.environment == "development" else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router)
    app.include_router(authorize_router)
    app.include_router(dataset_router)
    app.include_router(pipeline_router)
    app.include_router(mqtt_router)

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception", exc_info=exc)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return app

