# Deployment

This document covers configuration, deployment options, and production considerations for the CELINE Policy Service.

## Configuration

All configuration is via environment variables with the `CELINE_` prefix.

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CELINE_ENVIRONMENT` | `development` | Environment name (development, staging, production) |
| `CELINE_LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### OIDC / JWT Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CELINE_OIDC_ISSUER` | `http://keycloak:8080/realms/celine` | JWT issuer URL |
| `CELINE_OIDC_AUDIENCE` | (none) | Expected audience claim (optional) |
| `CELINE_JWKS_CACHE_TTL_SECONDS` | `3600` | JWKS cache TTL |
| `CELINE_JWT_ALGORITHMS` | `["RS256"]` | Allowed JWT algorithms |

### Policy Engine Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CELINE_POLICIES_DIR` | `policies` | Path to Rego policies |
| `CELINE_DATA_DIR` | `policies/data` | Path to policy data (JSON) |

### Decision Cache Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CELINE_DECISION_CACHE_ENABLED` | `true` | Enable decision caching |
| `CELINE_DECISION_CACHE_TTL_SECONDS` | `300` | Cache TTL |
| `CELINE_DECISION_CACHE_MAXSIZE` | `10000` | Maximum cache entries |

### Audit Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CELINE_AUDIT_ENABLED` | `true` | Enable audit logging |
| `CELINE_AUDIT_LOG_INPUTS` | `true` | Log full policy inputs |

---

## Docker Deployment

### Dockerfile

```dockerfile
# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app
COPY . /app
RUN uv sync --frozen

FROM python:3.12-slim
WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/policies /app/policies
COPY --from=builder /app/src /app/src

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV CELINE_POLICIES_DIR=/app/policies
ENV CELINE_DATA_DIR=/app/policies/data

EXPOSE 8009

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8009/health').raise_for_status()"

CMD ["uvicorn", "celine.policies.main:create_app", "--host", "0.0.0.0", "--port", "8009"]
```

### Docker Compose (Development)

```yaml
version: "3.8"

services:
  policy-service:
    build: .
    ports:
      - "8009:8009"
    environment:
      - CELINE_ENVIRONMENT=development
      - CELINE_LOG_LEVEL=DEBUG
      - CELINE_OIDC_ISSUER=http://keycloak:8080/realms/celine
      - CELINE_DECISION_CACHE_TTL_SECONDS=60
    volumes:
      - ./policies:/app/policies:ro
    depends_on:
      keycloak:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8009/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  keycloak:
    image: quay.io/keycloak/keycloak:latest
    command: start-dev --import-realm
    environment:
      - KC_BOOTSTRAP_ADMIN_USERNAME=admin
      - KC_BOOTSTRAP_ADMIN_PASSWORD=admin
      - KC_HTTP_PORT=8080
      - KC_HOSTNAME=keycloak
    volumes:
      - ./config/keycloak/import:/opt/keycloak/data/import:ro
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/localhost/8080"]
      interval: 5s
      timeout: 5s
      retries: 15

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

---

## Kubernetes Deployment

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: policy-service
  labels:
    app: policy-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: policy-service
  template:
    metadata:
      labels:
        app: policy-service
    spec:
      containers:
        - name: policy-service
          image: celine/policy-service:latest
          ports:
            - containerPort: 8009
          env:
            - name: CELINE_ENVIRONMENT
              value: production
            - name: CELINE_LOG_LEVEL
              value: INFO
            - name: CELINE_OIDC_ISSUER
              valueFrom:
                configMapKeyRef:
                  name: policy-service-config
                  key: oidc-issuer
            - name: CELINE_DECISION_CACHE_ENABLED
              value: "true"
            - name: CELINE_DECISION_CACHE_TTL_SECONDS
              value: "300"
          resources:
            requests:
              memory: "256Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /health
              port: 8009
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8009
            initialDelaySeconds: 5
            periodSeconds: 5
          volumeMounts:
            - name: policies
              mountPath: /app/policies
              readOnly: true
      volumes:
        - name: policies
          configMap:
            name: policy-service-policies
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: policy-service
spec:
  selector:
    app: policy-service
  ports:
    - port: 8009
      targetPort: 8009
  type: ClusterIP
```

### ConfigMap for Policies

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: policy-service-policies
data:
  # Policies loaded from files
  # Or use a volume mount from a git-sync sidecar
```

### HorizontalPodAutoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: policy-service
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: policy-service
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

---

## Production Checklist

### Security

- [ ] **TLS enabled** between services and policy service
- [ ] **Network policies** restricting access to policy service
- [ ] **Secrets management** for any sensitive configuration
- [ ] **Audit logs** forwarded to centralized logging (SIEM)
- [ ] **Rate limiting** configured at ingress/load balancer
- [ ] **OIDC issuer** uses HTTPS in production

### Reliability

- [ ] **Multiple replicas** (minimum 2 for HA)
- [ ] **Health checks** configured for liveness and readiness
- [ ] **Resource limits** set appropriately
- [ ] **PodDisruptionBudget** configured
- [ ] **Graceful shutdown** handling

### Monitoring

- [ ] **Metrics endpoint** exposed (Prometheus format)
- [ ] **Dashboards** for request rate, latency, error rate
- [ ] **Alerts** for high error rate, latency spikes
- [ ] **Log aggregation** configured

### Performance

- [ ] **Decision cache** enabled with appropriate TTL
- [ ] **JWKS cache** TTL appropriate for key rotation frequency
- [ ] **Connection pooling** if using external data sources
- [ ] **Load testing** completed

---

## Monitoring

### Prometheus Metrics

The service exposes metrics at `/metrics` (if enabled):

```
# Request metrics
policy_requests_total{endpoint="/authorize", status="200"} 12345
policy_request_duration_seconds{endpoint="/authorize", quantile="0.99"} 0.005

# Decision metrics
policy_decisions_total{policy="celine.dataset.access", allowed="true"} 10000
policy_decisions_total{policy="celine.dataset.access", allowed="false"} 500

# Cache metrics
policy_cache_hits_total 8000
policy_cache_misses_total 4500

# Engine metrics
policy_evaluation_duration_seconds{quantile="0.99"} 0.001
```

### Grafana Dashboard

Key panels to include:

1. **Request Rate** — Requests per second by endpoint
2. **Latency** — P50, P95, P99 latency
3. **Error Rate** — 4xx and 5xx responses
4. **Decision Distribution** — Allow vs deny by policy
5. **Cache Hit Rate** — Cache effectiveness
6. **Policy Evaluation Time** — OPA performance

### Alerting Rules

```yaml
groups:
  - name: policy-service
    rules:
      - alert: HighErrorRate
        expr: |
          sum(rate(policy_requests_total{status=~"5.."}[5m]))
          / sum(rate(policy_requests_total[5m])) > 0.01
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Policy service error rate > 1%"

      - alert: HighLatency
        expr: |
          histogram_quantile(0.99, rate(policy_request_duration_seconds_bucket[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Policy service P99 latency > 100ms"

      - alert: LowCacheHitRate
        expr: |
          policy_cache_hits_total / (policy_cache_hits_total + policy_cache_misses_total) < 0.5
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Policy cache hit rate < 50%"
```

---

## Troubleshooting

### Service Won't Start

**Check policies are valid:**
```bash
opa check policies/
opa test policies/ -v
```

**Check Keycloak connectivity:**
```bash
curl http://keycloak:8080/realms/celine/.well-known/openid-configuration
```

### JWT Validation Failing

**Decode and inspect the token:**
```bash
# Decode JWT (without verification)
echo $TOKEN | cut -d. -f2 | base64 -d | jq
```

**Check issuer matches:**
```bash
# Token issuer
echo $TOKEN | cut -d. -f2 | base64 -d | jq -r '.iss'

# Expected issuer
echo $CELINE_OIDC_ISSUER
```

### Policy Evaluation Errors

**Test policy locally:**
```bash
opa eval -d policies/ -i input.json "data.celine.dataset.access"
```

**Check policy logs:**
```bash
# Enable debug logging
CELINE_LOG_LEVEL=DEBUG uvicorn celine.policies.main:create_app
```

### High Latency

**Check cache effectiveness:**
```bash
curl http://localhost:8009/ready | jq '.details.cache'
```

**Profile OPA evaluation:**
```bash
opa eval -d policies/ -i input.json --profile "data.celine.dataset.access"
```

---

## Upgrades and Rollbacks

### Policy Updates

Policies can be hot-reloaded without restart:

```bash
# Update policies on disk, then:
curl -X POST http://localhost:8009/reload
```

### Service Updates

1. **Deploy new version** alongside existing
2. **Run smoke tests** against new version
3. **Gradually shift traffic** (if using service mesh)
4. **Monitor for errors**
5. **Rollback if needed** by reverting deployment

### Rollback Procedure

```bash
# Kubernetes
kubectl rollout undo deployment/policy-service

# Docker Compose
docker compose up -d --force-recreate policy-service
```
