"""FastAPI application for MQTT authentication."""

import logging

from celine.sdk.policies import CachedPolicyEngine, DecisionCache, PolicyEngine
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from celine.mqtt_auth.config import MqttAuthSettings
from celine.mqtt_auth.routes import get_engine, get_settings, router

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application
    """
    settings = MqttAuthSettings()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Initialize policy engine
    logger.info("Loading policies from %s", settings.policies_dir)
    engine = PolicyEngine(
        policies_dir=settings.policies_dir,
        data_dir=settings.policies_data_dir,
    )
    engine.load()

    # Wrap with cache if enabled
    if settings.policies_cache_enabled:
        logger.info(
            "Policy cache enabled: ttl=%ds maxsize=%d",
            settings.policies_cache_ttl,
            settings.policies_cache_maxsize,
        )
        cache = DecisionCache(
            maxsize=settings.policies_cache_maxsize,
            ttl_seconds=settings.policies_cache_ttl,
        )
        cached_engine = CachedPolicyEngine(
            engine=engine,
            cache=cache,
            enabled=True,
        )
    else:
        logger.info("Policy cache disabled")
        cached_engine = CachedPolicyEngine(
            engine=engine,
            enabled=False,
        )

    logger.info(
        "Loaded %d policies from %d packages: %s",
        engine.policy_count,
        len(engine.get_packages()),
        engine.get_packages(),
    )

    # Create FastAPI app
    app = FastAPI(
        title="CELINE MQTT Auth Service",
        description="Authentication and authorization for MQTT broker using policies",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Store settings and engine in app state
    app.state.settings = settings
    app.state.engine = cached_engine

    # Override dependencies to use app state
    app.dependency_overrides[get_settings] = lambda: app.state.settings
    app.dependency_overrides[get_engine] = lambda: app.state.engine

    # Include MQTT routes
    app.include_router(router)

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "policies_loaded": engine.is_loaded,
            "policy_count": engine.policy_count,
            "packages": engine.get_packages(),
        }

    # Cache stats endpoint (if caching enabled)
    # if settings.policies_cache_enabled:

    #     @app.get("/stats/cache")
    #     async def cache_stats():
    #         """Get cache statistics."""
    #         return cached_engine.cache_stats

    # Reload policies endpoint (useful for development)
    # @app.post("/reload")
    # async def reload_policies():
    #     """Reload policies from disk."""
    #     logger.info("Reloading policies...")
    #     cached_engine.reload()
    #     logger.info("Policies reloaded: %d policies", engine.policy_count)
    #     return {
    #         "status": "reloaded",
    #         "policy_count": engine.policy_count,
    #         "packages": engine.get_packages(),
    #     }

    return app


# For running with uvicorn
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "celine.mqtt_auth.main:app",
        host="0.0.0.0",
        port=8009,
        reload=False,
    )
