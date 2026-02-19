# syntax=docker/dockerfile:1

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_SYSTEM_PYTHON=1

WORKDIR /app

# Install OS deps (build tools not strictly required for this set, keep lean)
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH=".venv/bin:/root/.local/bin:${PATH}"

# Copy dependency manifests first for better caching
COPY pyproject.toml README.md ./
COPY src ./src

RUN uv sync --no-editable

COPY policies ./policies

# Expose port
EXPOSE 8009

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8009/health').raise_for_status()"

# Run application
CMD [".venv/bin/uvicorn", "celine.mqtt_auth.main:create_app", "--host", "0.0.0.0", "--port", "8009"]
