# CELINE Policy Service

Centralized authorization service for the CELINE platform using embedded OPA (regorus).

## Overview

This service provides policy-based authorization for:
- **Dataset API** - Access control and row-level filtering
- **Pipeline Events** - State transition validation
- **Digital Twin** - API access and event emission
- **MQTT Broker** - Topic-based ACLs (mosquitto-go-auth compatible)
- **User Data** - Own-data access and delegation

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Policy Service                        │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Routes: /authorize, /dataset/*, /pipeline/*, /mqtt/*     │  │
│  └─────────────────────────┬─────────────────────────────────┘  │
│                            │                                     │
│  ┌─────────────────────────▼─────────────────────────────────┐  │
│  │  Policy Engine (regorus - embedded Rego)                  │  │
│  │  └── Decision Cache (LRU + TTL)                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  JWT Validator  │  │  Subject Extract │  │  Audit Logger   │  │
│  │  (JWKS cached)  │  │  (Keycloak)      │  │  (structured)   │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Using Docker Compose

```bash
# Start service with Keycloak
docker compose up -d

# Test health
curl http://localhost:8000/health

# Test authorization
curl -X POST http://localhost:8000/dataset/access \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-jwt>" \
  -d '{
    "dataset_id": "ds-123",
    "access_level": "internal",
    "action": "read"
  }'
```

### Local Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run OPA tests
opa test policies/ -v

# Start server
uvicorn celine_policies.main:app --reload
```

## Authorization Model

### Subject Types

| Type | Identified By | Authorization Via |
|------|---------------|-------------------|
| User | JWT `sub` claim | Group membership (`groups` claim) |
| Service | JWT `client_id` claim | OAuth scopes (`scope` claim) |
| Anonymous | No JWT | Limited to open resources |

### Group Hierarchy

```
admins (level 4) > managers (level 3) > editors (level 2) > viewers (level 1)
```

### Dataset Access Levels

| Level | Anonymous | Viewers | Editors | Managers | Admins |
|-------|-----------|---------|---------|----------|--------|
| open | read | read | read | read | read/write |
| internal | ❌ | read | read/write | read/write | read/write |
| restricted | ❌ | ❌ | ❌ | ❌ | read/write |

### Service Scopes

| Scope | Permissions |
|-------|-------------|
| `dataset.query` | Read internal datasets |
| `dataset.admin` | Read/write all datasets |
| `pipeline.execute` | Execute pipeline transitions |
| `dt.read` | Read dt data |
| `dt.write` | Write dt data |
| `mqtt.admin` | Full MQTT access |

## API Endpoints

### Generic Authorization

```
POST /authorize
```

Evaluates any policy based on resource type.

### Dataset

```
POST /dataset/access   - Check dataset access
POST /dataset/filters  - Get row-level filters
```

### Pipeline

```
POST /pipeline/transition  - Validate state transition
```

### MQTT (mosquitto-go-auth)

```
POST /mqtt/auth      - Authenticate user
POST /mqtt/acl       - Check topic ACL
POST /mqtt/superuser - Check superuser status
```

### Health

```
GET /health   - Liveness check
GET /ready    - Readiness check
POST /reload  - Reload policies
```

## Configuration

Environment variables (prefix: `CELINE_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | development | Environment name |
| `LOG_LEVEL` | INFO | Logging level |
| `OIDC_ISSUER` | http://keycloak.../realms/celine | JWT issuer |
| `POLICIES_DIR` | policies | Rego policies directory |
| `DATA_DIR` | data | Policy data directory |
| `DECISION_CACHE_ENABLED` | true | Enable decision caching |
| `DECISION_CACHE_TTL_SECONDS` | 300 | Cache TTL |

## Policy Structure

```
policies/
└── celine/
    ├── common/           # Shared helpers
    │   ├── subject.rego  # Subject type detection
    │   └── access_levels.rego
    ├── dataset/
    │   ├── access.rego   # Dataset access rules
    │   ├── row_filter.rego
    │   └── access_test.rego
    ├── pipeline/
    │   └── state.rego    # State machine
    ├── dt/
    │   └── access.rego
    ├── mqtt/
    │   └── acl.rego
    └── userdata/
        └── access.rego
```

## Testing

### Python Tests

```bash
pytest tests/python -v
```

### Rego Policy Tests

```bash
opa test policies/ -v
```

### Integration Tests

```bash
# Start services
docker compose up -d

# Run integration tests
pytest tests/integration -v
```

## Audit Logging

All decisions are logged with:

```json
{
  "event": "policy_decision",
  "request_id": "uuid",
  "allowed": true,
  "policy": "celine.dataset.access",
  "subject_id": "user-123",
  "subject_type": "user",
  "resource_type": "dataset",
  "resource_id": "ds-456",
  "action": "read",
  "latency_ms": 0.5,
  "cached": false
}
```

## Performance

- **Embedded OPA**: ~0.1-0.5ms per evaluation
- **Decision Cache**: Configurable LRU + TTL
- **JWKS Cache**: 1 hour TTL with refresh on failure

## MQTT Integration

Configure mosquitto-go-auth:

```
auth_opt_backends http
auth_opt_http_host policy-service
auth_opt_http_port 8000
auth_opt_http_getuser_uri /mqtt/auth
auth_opt_http_aclcheck_uri /mqtt/acl
auth_opt_http_superuser_uri /mqtt/superuser
```

## License

Internal use only.
