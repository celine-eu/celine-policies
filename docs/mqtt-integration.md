# MQTT Integration

This document covers MQTT authorization, topic patterns, Rego policies, and broker configuration.

## Overview

The CELINE MQTT setup consists of:

- **Mosquitto** with [mosquitto-go-auth](https://github.com/iegomez/mosquitto-go-auth) plugin
- **MQTT auth service** (`celine.mqtt_auth`) as the HTTP backend
- **Rego policies** (`policies/celine/mqtt/acl.rego` + `policies/celine/scopes.rego`) evaluated via regorus

MQTT clients authenticate with a JWT (obtained from Keycloak) passed as the MQTT password.

## Authentication Flow

1. Client connects to Mosquitto with JWT as password
2. Mosquitto calls `POST /user` on the auth service
3. Auth service validates JWT signature, issuer, and expiry
4. On publish/subscribe, Mosquitto calls `POST /acl`
5. Auth service evaluates the `celine.mqtt.acl` Rego policy
6. Superuser check via `POST /superuser` is disabled by default in the mosquitto config (`auth_opt_disable_superuser true`)

## Topic Naming Convention

```
celine/{service}/{resource}/{...}
```

The ACL policy parses topics by splitting on `/` and derives the required scope as `{service}.{resource}.{verb}`.

Examples:

| Topic | Action | Required Scope |
|-------|--------|----------------|
| `celine/pipelines/runs/pipeline-123` | subscribe | `pipelines.runs.read` |
| `celine/digital-twin/events/pump/pump-001` | publish | `digital-twin.events.write` |
| `celine/flexibility/committed/flex-456` | subscribe | `flexibility.committed.read` |
| `celine/nudging/ingest/user-789` | publish | `nudging.ingest.write` |

## ACL Policy Rules

The policy (`policies/celine/mqtt/acl.rego`) evaluates access based on topic shape:

### Service-level topics (`celine/{service}`)

Access to `celine/{service}` (no resource path) requires one of:
- Service admin scope (`{service}.admin`)
- Global admin group (`admin` or `mqtt.admin`)
- Service admin group (`{service}.admin` or `mqtt:{service}:admin`)

### Service wildcard topics (`celine/{service}/#` or `celine/{service}/+`)

Same requirements as service-level topics — only admins can use service-wide wildcards.

### Resource topics (`celine/{service}/{resource}/{...}`)

Standard topic access requires either:

**For service clients:**
- Exact scope match (`{service}.{resource}.{verb}`)
- Service admin scope (`{service}.admin`)
- Resource wildcard scope (`{service}.{resource}.*`)

**For users:**
- Exact group match (`{service}.{resource}.{verb}` or `mqtt:{service}:{resource}:{verb}`)
- Resource wildcard group (`{service}.{resource}.*` or `mqtt:{service}:{resource}:*`)
- Service admin group
- Global admin group

### Action mapping

| MQTT action | Rego verb |
|---|---|
| `subscribe` | `read` |
| `read` | `read` |
| `publish` | `write` |

## Mosquitto Configuration

The broker config is at `config/mosquitto/mosquitto.conf`:

```ini
listener 1883           # MQTT
listener 1884           # WebSockets
protocol mqtt / websockets

auth_plugin /mosquitto/go-auth.so
auth_opt_backends jwt
auth_opt_jwt_mode remote
auth_opt_jwt_host host.docker.internal
auth_opt_jwt_port 8009

auth_opt_jwt_getuser_uri    /user
auth_opt_jwt_aclcheck_uri   /acl
auth_opt_jwt_superuser_uri  /superuser

auth_opt_disable_superuser true

# Redis caching (disabled by default, redis is available in compose)
auth_opt_cache false
auth_opt_cache_type redis
auth_opt_cache_host host.docker.internal
auth_opt_cache_port 6379
```

The broker uses the JWT backend mode (`auth_opt_backends jwt`), not the HTTP backend. The JWT is extracted by mosquitto-go-auth and forwarded to the auth service endpoints.

## Docker Compose

The relevant services in `docker-compose.yaml`:

```yaml
mqtt_auth:          # FastAPI auth service on port 8009
mosquitto:          # Mosquitto broker on ports 1883 (MQTT) + 1884 (WS)
redis:              # Redis for optional auth caching
```

Mosquitto depends on `mqtt_auth` being healthy before starting.

## Client Examples

### Python (paho-mqtt)

```python
import paho.mqtt.client as mqtt

token = get_jwt_from_keycloak()

client = mqtt.Client()
client.username_pw_set(username="", password=token)
client.connect("localhost", 1883)

# Subscribe (requires {service}.{resource}.read scope/group)
client.subscribe("celine/digital-twin/events/#")

# Publish (requires {service}.{resource}.write scope/group)
client.publish("celine/digital-twin/events/pump/pump-001", payload='{"state": "running"}')
```

### Service Account

Service clients use client_credentials flow to get a JWT with the scopes defined in `clients.yaml`:

```python
import httpx

response = httpx.post(
    "http://keycloak.celine.localhost/realms/celine/protocol/openid-connect/token",
    data={
        "grant_type": "client_credentials",
        "client_id": "svc-digital-twin",
        "client_secret": "your-secret",
    },
)
token = response.json()["access_token"]
```

## Debugging

### Test authentication

```bash
TOKEN=$(curl -s -X POST \
  "http://localhost:8080/realms/celine/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=svc-digital-twin" \
  -d "client_secret=svc-digital-twin" \
  | jq -r '.access_token')

curl -X POST http://localhost:8009/user \
  -H "Authorization: Bearer $TOKEN"
```

### Test ACL

```bash
curl -X POST http://localhost:8009/acl \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"clientid": "test", "topic": "celine/digital-twin/events/pump/1", "acc": 2}'
```

### Check health

```bash
curl http://localhost:8009/health
```

### Decode JWT claims

```bash
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq
```
