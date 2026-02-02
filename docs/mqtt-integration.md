# MQTT Integration

This document covers MQTT authorization, topic patterns, and broker configuration for the CELINE platform.

## Overview

The policy service provides MQTT authorization via HTTP backend endpoints compatible with [mosquitto-go-auth](https://github.com/iegomez/mosquitto-go-auth).

```
┌─────────────┐        ┌─────────────┐        ┌─────────────────┐
│ MQTT Client │───────▶│  Mosquitto  │───────▶│ Policy Service  │
│  (+ JWT)    │        │   Broker    │  HTTP  │  /mqtt/user     │
└─────────────┘        └─────────────┘        │  /mqtt/acl      │
                                              │  /mqtt/superuser│
                                              └─────────────────┘
```

## Authentication Flow

1. Client connects to Mosquitto with JWT as password (or in Authorization header)
2. Mosquitto calls `/mqtt/user` to validate the JWT
3. On publish/subscribe, Mosquitto calls `/mqtt/acl` to check topic permissions
4. Optionally, `/mqtt/superuser` grants full access to admin users

## Topic Naming Convention

### Recommended Pattern

```
celine/{service}/{resource-type}/{resource-id}/{action-or-data}
```

### Topic Hierarchy

```
celine/
├── digital-twin/
│   ├── events/{entity_type}/{entity_id}        # DT state change events
│   │   └── e.g., celine/digital-twin/events/pump/pump-001
│   ├── state/{entity_type}/{entity_id}         # Current state (retained)
│   │   └── e.g., celine/digital-twin/state/pump/pump-001
│   ├── commands/{entity_type}/{entity_id}      # Commands to DT
│   │   └── e.g., celine/digital-twin/commands/pump/pump-001
│   └── simulation/{run_id}/+                   # Simulation outputs
│       └── e.g., celine/digital-twin/simulation/sim-123/results
│
├── pipelines/
│   ├── status/{pipeline_id}                    # Pipeline status
│   │   └── e.g., celine/pipelines/status/etl-daily
│   └── events/{pipeline_id}/{event_type}       # Pipeline events
│       └── e.g., celine/pipelines/events/etl-daily/started
│
├── rec-registry/
│   └── updates/{rec_type}/{rec_id}             # Registry updates
│       └── e.g., celine/rec-registry/updates/certificate/cert-456
│
├── nudging/
│   ├── triggers/{user_id}                      # Nudge triggers
│   │   └── e.g., celine/nudging/triggers/user-789
│   └── responses/{user_id}                     # User responses
│       └── e.g., celine/nudging/responses/user-789
│
├── telemetry/
│   └── {device_type}/{device_id}/readings      # Raw sensor data
│       └── e.g., celine/telemetry/meter/meter-001/readings
│
└── system/
    ├── alerts/{severity}                       # System alerts
    └── health/{service}                        # Service health
```

## MQTT Scopes

| Scope | Permissions | Typical Use |
|-------|-------------|-------------|
| `mqtt.read` | Subscribe, Read | Consumers, dashboards |
| `mqtt.write` | Publish | Producers, services |
| `mqtt.admin` | All + Superuser | Admin tools, debugging |

## ACL Configuration

ACL rules are defined in `policies/data/celine.json`:

```json
{
  "celine": {
    "mqtt": {
      "acl": {
        "rules": [
          {
            "subjects": { "groups": ["admins"] },
            "topics": ["#"],
            "actions": "*",
            "effect": "allow"
          },
          {
            "subjects": {
              "types": ["service"],
              "scopes": ["mqtt.write"]
            },
            "topics": ["celine/digital-twin/events/#"],
            "actions": ["publish"],
            "effect": "allow"
          }
        ]
      }
    },
    "roles": {
      "group_permissions": {
        "admins": ["subscribe", "read", "publish", "superuser"],
        "managers": ["subscribe", "read", "publish"],
        "editors": ["subscribe", "read", "publish"],
        "viewers": ["subscribe", "read"]
      },
      "scope_permissions": {
        "mqtt.admin": ["subscribe", "read", "publish", "superuser"],
        "mqtt.read": ["subscribe", "read"],
        "mqtt.write": ["publish"]
      }
    }
  }
}
```

### ACL Rule Structure

```json
{
  "subjects": {
    "types": ["user", "service"],
    "ids": ["specific-client-id"],
    "groups": ["viewers", "editors"],
    "scopes": ["mqtt.read", "mqtt.write"]
  },
  "topics": ["celine/telemetry/#", "celine/+/events/+"],
  "actions": ["subscribe", "read", "publish"],
  "effect": "allow"
}
```

| Field | Description |
|-------|-------------|
| `subjects.types` | Filter by subject type (`user`, `service`) |
| `subjects.ids` | Filter by specific client/user IDs |
| `subjects.groups` | Filter by user groups |
| `subjects.scopes` | Filter by OAuth scopes |
| `topics` | Topic patterns (supports `+` and `#` wildcards) |
| `actions` | `subscribe`, `read`, `publish` |
| `effect` | `allow` or `deny` (default: `allow`) |

### Topic Wildcards

| Wildcard | Matches | Example |
|----------|---------|---------|
| `+` | Single level | `celine/+/events` matches `celine/dt/events` |
| `#` | Multiple levels | `celine/dt/#` matches `celine/dt/state/pump/1` |

## Example ACL Rules

### Service Publishing to Its Namespace

```json
{
  "subjects": {
    "types": ["service"],
    "scopes": ["mqtt.write"]
  },
  "topics": ["celine/digital-twin/events/#", "celine/digital-twin/state/#"],
  "actions": ["publish"],
  "effect": "allow"
}
```

### Users Subscribing to Telemetry

```json
{
  "subjects": {
    "types": ["user"],
    "groups": ["viewers"]
  },
  "topics": ["celine/telemetry/+/+/readings"],
  "actions": ["subscribe", "read"],
  "effect": "allow"
}
```

### Pipeline Service Status Updates

```json
{
  "subjects": {
    "types": ["service"],
    "ids": ["svc-pipelines"]
  },
  "topics": ["celine/pipelines/status/+", "celine/pipelines/events/#"],
  "actions": ["publish"],
  "effect": "allow"
}
```

### Deny Specific Topic

```json
{
  "subjects": {
    "types": ["user"],
    "groups": ["viewers"]
  },
  "topics": ["celine/system/alerts/critical"],
  "actions": ["subscribe"],
  "effect": "deny"
}
```

## Mosquitto Configuration

### mosquitto.conf

```ini
# Listener
listener 1883
protocol mqtt

# TLS (recommended for production)
listener 8883
protocol mqtt
cafile /etc/mosquitto/certs/ca.crt
certfile /etc/mosquitto/certs/server.crt
keyfile /etc/mosquitto/certs/server.key
require_certificate false

# Auth plugin
auth_plugin /usr/lib/mosquitto-go-auth.so

# HTTP backend
auth_opt_backends http
auth_opt_http_host policy-service
auth_opt_http_port 8009

# Endpoints
auth_opt_http_getuser_uri /mqtt/user
auth_opt_http_aclcheck_uri /mqtt/acl
auth_opt_http_superuser_uri /mqtt/superuser

# HTTP options
auth_opt_http_method POST
auth_opt_http_content_type application/json
auth_opt_http_timeout 5

# Pass JWT in Authorization header
auth_opt_http_params_mode form
auth_opt_http_with_tls false

# Caching (optional)
auth_opt_cache true
auth_opt_cache_type redis
auth_opt_cache_host redis
auth_opt_cache_port 6379
auth_opt_auth_cache_seconds 300
auth_opt_acl_cache_seconds 300
```

### Docker Compose

```yaml
services:
  mosquitto:
    image: ghcr.io/lhns/mosquitto-go-auth:latest
    ports:
      - "1883:1883"
      - "8883:8883"
    volumes:
      - ./config/mosquitto:/etc/mosquitto:ro
    depends_on:
      - policy-service
      - redis
    environment:
      - POLICY_SERVICE_HOST=policy-service
      - POLICY_SERVICE_PORT=8009

  redis:
    image: redis:7-alpine
    # Caches auth decisions
```

## Client Integration

### Python (paho-mqtt)

```python
import paho.mqtt.client as mqtt

def get_jwt_token() -> str:
    # Get token from Keycloak
    ...

client = mqtt.Client()

# Use JWT as password
client.username_pw_set(
    username="",  # Empty or client ID
    password=get_jwt_token()
)

# Or with TLS
client.tls_set(
    ca_certs="/path/to/ca.crt",
    certfile="/path/to/client.crt",
    keyfile="/path/to/client.key"
)

client.connect("mqtt.celine.example", 8883)

# Subscribe (requires mqtt.read scope)
client.subscribe("celine/digital-twin/events/#")

# Publish (requires mqtt.write scope)
client.publish(
    "celine/digital-twin/events/pump/pump-001",
    payload='{"state": "running"}'
)
```

### JavaScript (mqtt.js)

```javascript
const mqtt = require('mqtt');

const token = await getJwtToken();

const client = mqtt.connect('mqtts://mqtt.celine.example:8883', {
  username: '',
  password: token,
  rejectUnauthorized: true,
});

client.on('connect', () => {
  client.subscribe('celine/digital-twin/events/#');
});

client.on('message', (topic, message) => {
  console.log(`${topic}: ${message.toString()}`);
});
```

### Service Account (Client Credentials)

```python
import httpx
import paho.mqtt.client as mqtt

async def get_service_token():
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://keycloak:8080/realms/celine/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "svc-digital-twin",
                "client_secret": "secret",
                "scope": "mqtt.write",
            }
        )
        return response.json()["access_token"]

# Token refresh should happen before expiry
token = await get_service_token()

mqtt_client = mqtt.Client()
mqtt_client.username_pw_set("", token)
mqtt_client.connect("mqtt.celine.example", 1883)
```

## Debugging

### Check Authentication

```bash
# Get a token
TOKEN=$(curl -s -X POST \
  "http://localhost:8080/realms/celine/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=svc-test" \
  -d "client_secret=secret" \
  | jq -r '.access_token')

# Test auth endpoint
curl -X POST http://localhost:8009/mqtt/user \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

### Check ACL

```bash
curl -X POST http://localhost:8009/mqtt/acl \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "topic": "celine/digital-twin/events/pump/1",
    "acc": 2
  }'
```

### Mosquitto Logs

```bash
# Enable verbose logging
mosquitto -v

# Or in config
log_type all
log_dest stderr
```

## Best Practices

### Topic Design

1. **Use hierarchical topics** — Enables efficient wildcard subscriptions
2. **Include service name** — `celine/{service}/...` for clear ownership
3. **Be consistent** — Same pattern across all services
4. **Use retained messages** for state — `celine/dt/state/...` with retain flag

### Security

1. **Use TLS in production** — Port 8883 with certificates
2. **Rotate tokens** — Handle token refresh before expiry
3. **Principle of least privilege** — Only grant necessary topics
4. **Monitor subscriptions** — Watch for unexpected wildcard subscriptions

### Performance

1. **Cache auth decisions** — Use Redis cache with mosquitto-go-auth
2. **Batch messages** — Avoid excessive small messages
3. **Use QoS appropriately** — QoS 0 for telemetry, QoS 1 for commands
4. **Limit retained messages** — Don't retain high-frequency data
