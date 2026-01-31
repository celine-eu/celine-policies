"""CELINE Policy Service - FastAPI Application."""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from celine.policies.audit import configure_audit_logging
from celine.policies.config import settings
from celine.policies.logs import configure_logging as configure_app_logging
from celine.policies.routes.deps import init_deps
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

    app = FastAPI(
        title="CELINE Policy Service",
        description="Centralized authorization service for the CELINE platform",
        version="0.1.0",
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

    app.include_router(health_router)
    app.include_router(authorize_router)
    app.include_router(dataset_router)
    app.include_router(pipeline_router)
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
