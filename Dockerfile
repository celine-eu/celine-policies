# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.9.27 /uv /uvx /bin/

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN uv sync

ENV PATH="/root/.local/bin/:/app/.venv/bin:$PATH"

# Production image
FROM python:3.12-slim

WORKDIR /app

# Create non-root user
RUN groupadd -r celine && useradd -r -g celine celine

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application
COPY src/celine /app/celine
COPY policies /app/policies
COPY data /app/data

# Set ownership
RUN chown -R celine:celine /app

USER celine

# Environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CELINE_POLICIES_DIR=/app/policies \
    CELINE_DATA_DIR=/app/data \
    CELINE_HOST=0.0.0.0 \
    CELINE_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

CMD ["uvicorn", "celine_policies.main:app", "--host", "0.0.0.0", "--port", "8000"]
