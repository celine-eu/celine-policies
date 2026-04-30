# API Reference

HTTP endpoints exposed by the MQTT auth service (`celine.mqtt_auth`).

## Base URL

| Environment | URL |
|-------------|-----|
| Development | `http://localhost:8009` |
| Docker Compose | `http://mqtt_auth:8009` |

## Authentication

All endpoints (except `/health`) require a JWT in the `Authorization` header:

```
Authorization: Bearer <jwt-token>
```

The JWT is validated using the OIDC configuration from `celine-sdk` (`OidcSettings`).

---

## POST /user

Authenticate an MQTT client. Called by mosquitto-go-auth on client connect.

Extracts the JWT from the `Authorization` header, validates it, and returns success if the token is valid.

**Response (200):**

```json
{"ok": true, "reason": "authenticated"}
```

**Response (403):**

```json
{"ok": false, "reason": "missing token"}
```

```json
{"ok": false, "reason": "invalid credentials"}
```

---

## POST /acl

Authorize MQTT topic access. Called by mosquitto-go-auth on every publish/subscribe.

Validates the JWT, converts the mosquitto `acc` bitmask to action names, and evaluates the `celine.mqtt.acl` Rego policy for each action.

**Request Body (JSON):**

```json
{
  "clientid": "my-client",
  "topic": "celine/digital-twin/events/pump/pump-001",
  "acc": 2
}
```

| Field | Type | Description |
|-------|------|-------------|
| `clientid` | string | MQTT client ID |
| `topic` | string | MQTT topic being accessed |
| `acc` | int | Access bitmask: 1=read, 2=publish, 4=subscribe |

**Access bitmask values:**

| Value | Permission |
|-------|------------|
| 1 | Read |
| 2 | Publish |
| 4 | Subscribe |
| 3 | Read + Publish |
| 5 | Read + Subscribe |
| 7 | All |

**Response (200):**

```json
{"ok": true, "reason": "authorized"}
```

**Response (403):**

```json
{"ok": false, "reason": "denied"}
```

---

## POST /superuser

Check if a client has MQTT superuser access. Superusers bypass all ACL checks.

Grants superuser if the JWT contains:
- The `mqtt.admin` scope, OR
- The `admin` group, OR
- The `mqtt.admin` group

**Request Body (JSON):**

```json
{
  "username": "client-id-or-jwt"
}
```

**Response (200):**

```json
{"ok": true, "reason": "superuser"}
```

**Response (403):**

```json
{"ok": false, "reason": "not superuser"}
```

---

## GET /health

Liveness check. No authentication required.

**Response:**

```json
{
  "status": "healthy",
  "policies_loaded": true,
  "policy_count": 2,
  "packages": ["celine.mqtt.acl", "celine.scopes"]
}
```

---

## GET /docs

Swagger UI for interactive API exploration.

## GET /redoc

ReDoc API documentation.

---

## Error Responses

| Code | Meaning |
|------|---------|
| 200 | OK (check `ok` field for auth result) |
| 403 | Authentication/authorization failed |
| 500 | Internal error (e.g. policy parse failure) |

The MQTT auth endpoints always return a `MqttResponse` body with `ok` and `reason` fields. HTTP status 403 is set alongside `ok: false` to satisfy mosquitto-go-auth's expected behavior.
