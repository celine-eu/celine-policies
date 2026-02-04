"""CELINE Policy Service - FastAPI Application."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from celine.policies.audit import configure_audit_logging
from celine.policies.config import settings
from celine.policies.logs import configure_logging as configure_app_logging
from celine.policies.routes import (
    authorize_router,
    health_router,
    mqtt_router,
)
from celine.policies.routes.deps import init_deps

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_app_logging()

    configure_audit_logging(
        log_level=settings.log_level,
        json_format=settings.environment != "development",
        service_name=settings.service_name,
    )

    logger.info("Starting CELINE Policy Service")

    await init_deps()

    logger.info("Service initialized")

    yield

    logger.info("Shutting down CELINE Policy Service")


def create_app() -> FastAPI:
    if os.getenv("DEBUG_ATTACH"):
        import debugpy

        debug_port = int(os.getenv("DEBUG_PORT", 5679))
        debugpy.listen(("0.0.0.0", debug_port))
        logger.info(f"Debugger listening on 0.0.0.0:{debug_port}")

        if os.getenv("DEBUG_ATTACH") == "wait":
            debugpy.wait_for_client()

    app = FastAPI(
        title="CELINE Policy Service",
        description="Centralized authorization service for the CELINE platform",
        version="0.2.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Simplified routes: health, authorize, mqtt
    app.include_router(health_router)
    app.include_router(authorize_router)
    app.include_router(mqtt_router)

    @app.exception_handler(Exception)
    async def global_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception("Unhandled exception", exc_info=exc)
        return JSONResponse(
            status_code=500, content={"detail": "Internal server error"}
        )

    return app
