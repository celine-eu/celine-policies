# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:0.9.27 /uv /uvx /bin/

WORKDIR /app

# Copy project files
COPY pyproject.toml ./
COPY src ./src
COPY policies ./policies

# Install dependencies
RUN uv pip install --system --no-cache .

# Runtime stage
FROM python:3.12-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application and policies
COPY src ./src
COPY policies ./policies

# Environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CELINE_POLICIES_POLICIES_DIR=/app/policies \
    CELINE_LOG_LEVEL=INFO

# Expose port
EXPOSE 8009

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8009/health').raise_for_status()"

# Run application
CMD ["uvicorn", "celine.mqtt_auth.main:app", "--host", "0.0.0.0", "--port", "8009"]
