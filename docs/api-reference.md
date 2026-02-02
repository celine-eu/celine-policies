# API Reference

Complete documentation for all Policy Service endpoints.

## Base URL

| Environment | URL |
|-------------|-----|
| Development | `http://localhost:8009` |
| Docker Compose | `http://policy-service:8009` |
| Production | Configure via environment |

## Authentication

All authorization endpoints require a JWT in the `Authorization` header:

```
Authorization: Bearer <jwt-token>
```

The JWT must be issued by the configured Keycloak realm.

## Common Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes* | Bearer token (*except health endpoints) |
| `Content-Type` | Yes | `application/json` |
| `X-Request-Id` | No | Correlation ID for tracing |
| `X-Source-Service` | No | Calling service name (for audit) |

## Common Response Fields

All authorization responses include:

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | boolean | Whether the action is permitted |
| `reason` | string | Human-readable explanation |
| `request_id` | string | Request identifier for tracing |

---

## Authorization Endpoints

### POST /authorize

Generic authorization check for any resource type.

**Request Body:**

```json
{
  "resource": {
    "type": "dataset | pipeline | dt | topic | userdata",
    "id": "resource-identifier",
    "attributes": {
      "access_level": "open | internal | restricted"
    }
  },
  "action": {
    "name": "read | write | admin | ...",
    "context": {}
  },
  "context": {}
}
```

**Response:**

```json
{
  "allowed": true,
  "reason": "user has viewer access and client has dataset.query scope",
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Example:**

```bash
curl -X POST http://localhost:8009/authorize \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": {
      "type": "dataset",
      "id": "ds-energy-consumption",
      "attributes": {"access_level": "internal"}
    },
    "action": {"name": "read"}
  }'
```

---

## Dataset Endpoints

### POST /dataset/access

Check access to a specific dataset.

**Request Body:**

```json
{
  "dataset_id": "string",
  "access_level": "open | internal | restricted",
  "action": "read | write | admin"
}
```

**Response:**

```json
{
  "allowed": true,
  "reason": "user has viewer access and client has dataset.query scope",
  "request_id": "uuid"
}
```

**Access Matrix:**

| Level | Anonymous | Viewers | Editors | Managers | Admins |
|-------|-----------|---------|---------|----------|--------|
| open | read | read | read | read | read/write |
| internal | ❌ | read* | read/write* | read/write* | read/write |
| restricted | ❌ | ❌ | ❌ | ❌ | read/write* |

*Requires appropriate client scope (`dataset.query` or `dataset.admin`)

### POST /dataset/filters

Get row-level filters to apply to dataset queries.

**Request Body:**

```json
{
  "dataset_id": "string",
  "access_level": "open | internal | restricted"
}
```

**Response:**

```json
{
  "allowed": true,
  "filters": [
    {
      "field": "organization_id",
      "operator": "eq",
      "value": "org-123"
    },
    {
      "field": "classification",
      "operator": "in",
      "value": ["public", "internal"]
    }
  ],
  "reason": "filters applied based on user context",
  "request_id": "uuid"
}
```

**Filter Operators:**

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equals | `field = value` |
| `ne` | Not equals | `field != value` |
| `in` | In list | `field IN (values)` |
| `gt` | Greater than | `field > value` |
| `lt` | Less than | `field < value` |

---

## Pipeline Endpoints

### POST /pipeline/transition

Validate a pipeline state transition.

**Request Body:**

```json
{
  "pipeline_id": "string",
  "from_state": "pending | started | running | completed | failed | cancelled",
  "to_state": "pending | started | running | completed | failed | cancelled"
}
```

**Response:**

```json
{
  "allowed": true,
  "reason": "valid transition from started to running",
  "request_id": "uuid"
}
```

**Valid Transitions:**

```
pending ──▶ started ──▶ running ──▶ completed
   │           │           │
   │           │           └──▶ failed
   │           │
   │           └──▶ cancelled
   │
   └──▶ cancelled
```

---

## Digital Twin Endpoints

### POST /dt/access

Check access to digital twin operations.

**Request Body:**

```json
{
  "dt_id": "string",
  "action": "read | write | simulate | admin"
}
```

**Response:**

```json
{
  "allowed": true,
  "reason": "user can read dt data",
  "request_id": "uuid"
}
```

**Action Requirements:**

| Action | Users | Services |
|--------|-------|----------|
| `read` | viewers+ with `dt.read` | `dt.read` scope |
| `write` | editors+ with `dt.write` | `dt.write` scope |
| `simulate` | managers+ with `dt.simulate` | `dt.simulate` scope |
| `admin` | admins with `dt.admin` | `dt.admin` scope |

### POST /dt/event

Authorize a digital twin event emission.

**Request Body:**

```json
{
  "dt_id": "string",
  "event_type": "string",
  "simulation_state": "string | null"
}
```

**Response:**

```json
{
  "allowed": true,
  "reason": "service can emit dt events",
  "request_id": "uuid"
}
```

---

## MQTT Endpoints

Compatible with [mosquitto-go-auth](https://github.com/iegomez/mosquitto-go-auth) HTTP backend.

### POST /mqtt/user

Authenticate an MQTT client.

**Request:**

The JWT should be passed in the `Authorization` header:

```
Authorization: Bearer <jwt>
```

**Response:**

```json
{
  "ok": true,
  "reason": "authenticated"
}
```

**HTTP Status Codes:**

| Code | Meaning |
|------|---------|
| 200 | Authentication successful |
| 403 | Authentication failed |

### POST /mqtt/acl

Check topic access for an authenticated client.

**Request Body (form-encoded or JSON):**

```json
{
  "username": "jwt-token-or-username",
  "topic": "celine/digital-twin/events/pump/123",
  "clientid": "client-id",
  "acc": 1
}
```

**Access Mask (`acc`):**

| Value | Permission |
|-------|------------|
| 1 | Read |
| 2 | Write (Publish) |
| 4 | Subscribe |
| 3 | Read + Write |
| 5 | Read + Subscribe |
| 7 | All |

**Response:**

```json
{
  "ok": true,
  "reason": "authorized"
}
```

### POST /mqtt/superuser

Check if a client has superuser (admin) access.

**Request Body:**

```json
{
  "username": "jwt-token-or-username"
}
```

**Response:**

```json
{
  "ok": true,
  "reason": "superuser"
}
```

---

## User Data Endpoints

### POST /userdata/access

Check access to user-owned resources.

**Request Body:**

```json
{
  "resource_type": "dashboard | profile | settings",
  "resource_id": "string",
  "owner_id": "user-id-who-owns-resource",
  "action": "read | write | delete | share"
}
```

**Response:**

```json
{
  "allowed": true,
  "reason": "user accessing own data",
  "request_id": "uuid"
}
```

**Access Rules:**

| Scenario | Allowed |
|----------|---------|
| Owner accessing own data | ✅ |
| Resource shared with user | ✅ (read only) |
| Resource shared with user's group | ✅ (read only) |
| Admin with `userdata.admin` scope | ✅ |
| Other users | ❌ |

---

## Health Endpoints

### GET /health

Liveness check — is the service running?

**Response:**

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "policies_loaded": true,
  "details": {
    "policy_count": 6
  }
}
```

### GET /ready

Readiness check — is the service ready to accept requests?

**Response:**

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "policies_loaded": true,
  "details": {
    "policy_count": 6,
    "cache": {
      "hits": 1234,
      "misses": 56
    }
  }
}
```

### POST /reload

Hot-reload policies from disk.

**Response:**

```json
{
  "status": "success",
  "policy_count": 6
}
```

---

## Error Responses

### 400 Bad Request

Invalid request format or unknown resource type.

```json
{
  "detail": "Unknown resource type: invalid"
}
```

### 401 Unauthorized

Missing or invalid JWT.

```json
{
  "detail": "Invalid authorization header format"
}
```

### 403 Forbidden

Valid JWT but access denied (for MQTT endpoints).

```json
{
  "ok": false,
  "reason": "insufficient privileges"
}
```

### 500 Internal Server Error

Policy evaluation failure.

```json
{
  "detail": "Policy evaluation failed: ..."
}
```

---

## Rate Limiting

Production deployments should implement rate limiting. Recommended limits:

| Endpoint | Limit |
|----------|-------|
| `/authorize` | 1000 req/sec per client |
| `/health` | 100 req/sec |
| `/reload` | 1 req/min |

---

## OpenAPI Specification

The service exposes an OpenAPI spec at:

```
GET /openapi.json
GET /docs        # Swagger UI
GET /redoc       # ReDoc UI
```
