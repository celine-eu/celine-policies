"""CELINE Policy Service - FastAPI Application."""

from contextlib import asynccontextmanager

import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from celine.policies.audit import AuditLogger, configure_logging
from celine.policies.auth import JWKSCache, JWTValidator
from celine.policies.config import Settings, get_settings
from celine.policies.engine import CachedPolicyEngine, DecisionCache, PolicyEngine
from celine.policies.routes import (
    authorize_router,
    dataset_router,
    health_router,
    mqtt_router,
    pipeline_router,
)

# Global instances (initialized on startup)
_policy_engine: CachedPolicyEngine | None = None
_jwt_validator: JWTValidator | None = None
_audit_logger: AuditLogger | None = None

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def get_policy_engine() -> CachedPolicyEngine:
    """Get the policy engine instance."""
    if _policy_engine is None:
        raise RuntimeError("Policy engine not initialized")
    return _policy_engine


def get_jwt_validator() -> JWTValidator:
    """Get the JWT validator instance."""
    if _jwt_validator is None:
        raise RuntimeError("JWT validator not initialized")
    return _jwt_validator


def get_audit_logger() -> AuditLogger:
    """Get the audit logger instance."""
    if _audit_logger is None:
        raise RuntimeError("Audit logger not initialized")
    return _audit_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global _policy_engine, _jwt_validator, _audit_logger
    
    settings = get_settings()
    
    # Configure logging
    configure_logging(
        log_level=settings.log_level,
        json_format=settings.environment != "development",
        service_name=settings.service_name,
    )
    
    logger.info(
        "Starting CELINE Policy Service",
    )
    
    # Initialize policy engine
    engine = PolicyEngine(
        policies_dir=settings.policies_dir,
        data_dir=settings.data_dir,
    )
    engine.load()
    
    # Wrap with cache
    cache = DecisionCache(
        maxsize=settings.decision_cache_maxsize,
        ttl_seconds=settings.decision_cache_ttl_seconds,
    )
    _policy_engine = CachedPolicyEngine(
        engine=engine,
        cache=cache,
        cache_enabled=settings.decision_cache_enabled,
    )
    
    # Initialize JWT validator
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
    
    # Initialize audit logger
    _audit_logger = AuditLogger(
        enabled=settings.audit_enabled,
        log_inputs=settings.audit_log_inputs,
    )
    
    logger.info(
        "Service initialized",
    )
    
    yield
    
    # Cleanup
    logger.info("Shutting down CELINE Policy Service")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    if settings is None:
        settings = get_settings()
    
    app = FastAPI(
        title="CELINE Policy Service",
        description="Centralized authorization service for the CELINE platform",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.environment == "development" else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routers
    app.include_router(health_router)
    app.include_router(authorize_router)
    app.include_router(dataset_router)
    app.include_router(pipeline_router)
    app.include_router(mqtt_router)
    
    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception", exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )
    
    return app


# Default app instance for uvicorn
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    uvicorn.run(
        "celine.policies.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.environment == "development",
    )
