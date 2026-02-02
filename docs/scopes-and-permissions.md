# Scopes & Permissions

This document defines all OAuth scopes and their associated permissions in the CELINE platform.

## Understanding the Authorization Model

Authorization in CELINE requires **both** of the following to pass:

1. **User must have sufficient group level** (for user tokens)
2. **Client must have the required scope** (for all tokens)

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   User Token                    Service Token               │
│   ══════════                    ═════════════               │
│                                                             │
│   ┌─────────────┐               ┌─────────────┐            │
│   │ User Groups │               │   Scopes    │            │
│   │  (roles)    │               │   only      │            │
│   └──────┬──────┘               └──────┬──────┘            │
│          │                             │                    │
│          ▼                             │                    │
│   ┌─────────────┐                      │                    │
│   │Client Scopes│                      │                    │
│   └──────┬──────┘                      │                    │
│          │                             │                    │
│          ▼                             ▼                    │
│   ┌─────────────────────────────────────────┐              │
│   │              Authorization              │              │
│   │         (intersection of both)          │              │
│   └─────────────────────────────────────────┘              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## User Groups (Roles)

Users are assigned to groups in Keycloak. Groups form a hierarchy:

| Group | Level | Description |
|-------|-------|-------------|
| `admins` | 4 | Full platform access, restricted data |
| `managers` | 3 | Operational access, simulations, reports |
| `editors` | 2 | Write access to internal resources |
| `viewers` | 1 | Read-only access to internal resources |
| (none) | 0 | Anonymous, open resources only |

**Inheritance:** Higher levels include all permissions of lower levels.

### Group Assignment in Keycloak

Groups can be assigned via:
- Keycloak Admin Console → Users → Groups
- `realm_access.roles` claim in JWT
- `groups` claim in JWT (with `/` prefix stripped)

---

## OAuth Scopes

### Dataset Scopes

| Scope | Description | Permissions |
|-------|-------------|-------------|
| `dataset.query` | Query datasets | Read `open` and `internal` datasets |
| `dataset.admin` | Administer datasets | Read/write all datasets including `restricted` |

**Access Matrix (with scope):**

| Access Level | `dataset.query` | `dataset.admin` |
|--------------|-----------------|-----------------|
| `open` | read | read/write |
| `internal` | read | read/write |
| `restricted` | ❌ | read/write |

### Digital Twin Scopes

| Scope | Description | Permissions |
|-------|-------------|-------------|
| `dt.read` | Read digital twin data | Read twin state, history |
| `dt.write` | Write digital twin data | Update twin state |
| `dt.simulate` | Run simulations | Execute simulations on twins |
| `dt.admin` | Full digital twin access | All DT operations |

**Required Group Level:**

| Scope | User Group Required |
|-------|---------------------|
| `dt.read` | viewers+ |
| `dt.write` | editors+ |
| `dt.simulate` | managers+ |
| `dt.admin` | admins |

### Pipeline Scopes

| Scope | Description | Permissions |
|-------|-------------|-------------|
| `pipeline.execute` | Execute pipelines | Trigger state transitions |
| `pipeline.admin` | Administer pipelines | All pipeline operations |

### MQTT Scopes

| Scope | Description | Permissions |
|-------|-------------|-------------|
| `mqtt.read` | Subscribe and read | Subscribe to topics, read messages |
| `mqtt.write` | Publish messages | Publish to allowed topics |
| `mqtt.admin` | Full MQTT access | All topics, superuser status |

### User Data Scopes

| Scope | Description | Permissions |
|-------|-------------|-------------|
| `userdata.read` | Read user data | Read user's own data, shared data |
| `userdata.write` | Write user data | Modify user's own data |
| `userdata.admin` | Admin user data | Access any user's data |

---

## Service Client Configuration

Each CELINE service should have its own OAuth client with minimal required scopes.

### Recommended Client Configurations

#### digital-twin Service

```yaml
client_id: svc-digital-twin
client_type: confidential
service_account_enabled: true
scopes:
  - dt.read
  - dt.write
  - dt.simulate
  - dataset.query
  - mqtt.write
```

**Rationale:**
- Needs to read/write twin state (`dt.read`, `dt.write`)
- Runs simulations (`dt.simulate`)
- Queries datasets for twin configuration (`dataset.query`)
- Publishes twin events to MQTT (`mqtt.write`)

#### pipelines Service

```yaml
client_id: svc-pipelines
client_type: confidential
service_account_enabled: true
scopes:
  - pipeline.execute
  - dataset.query
  - dataset.admin
  - mqtt.write
```

**Rationale:**
- Manages pipeline state transitions (`pipeline.execute`)
- Reads input datasets (`dataset.query`)
- Writes output datasets (`dataset.admin`)
- Publishes pipeline status events (`mqtt.write`)

#### rec-registry Service

```yaml
client_id: svc-rec-registry
client_type: confidential
service_account_enabled: true
scopes:
  - dataset.query
  - dataset.admin
```

**Rationale:**
- Queries REC certificate data (`dataset.query`)
- Writes registry updates (`dataset.admin`)

#### nudging Service

```yaml
client_id: svc-nudging
client_type: confidential
service_account_enabled: true
scopes:
  - dt.read
  - userdata.read
  - mqtt.write
```

**Rationale:**
- Reads twin state for context (`dt.read`)
- Reads user preferences (`userdata.read`)
- Sends nudge notifications via MQTT (`mqtt.write`)

#### Frontend Application

```yaml
client_id: celine-frontend
client_type: public
scopes:
  - dt.read
  - dataset.query
  - userdata.read
  - userdata.write
```

**Rationale:**
- Public client (no secret, PKCE required)
- Read-only for twins and datasets
- Full access to user's own data

---

## Creating Scopes in Keycloak

### 1. Create Client Scopes

Navigate to: Keycloak Admin → Client Scopes → Create

```json
{
  "name": "dataset.query",
  "description": "Query datasets (read internal)",
  "protocol": "openid-connect",
  "attributes": {
    "include.in.token.scope": "true",
    "display.on.consent.screen": "true"
  }
}
```

Repeat for each scope.

### 2. Create Service Clients

Navigate to: Keycloak Admin → Clients → Create

```json
{
  "clientId": "svc-digital-twin",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "publicClient": false
}
```

### 3. Assign Scopes to Clients

Navigate to: Client → Client Scopes → Add client scope

Select the scopes required for this client (default or optional).

---

## Scope Validation Examples

### Example 1: User Reading Internal Dataset

**JWT Claims:**
```json
{
  "sub": "user-123",
  "realm_access": {"roles": ["viewers"]},
  "scope": "openid dataset.query"
}
```

**Policy Check:**
1. User is in `viewers` group (level 1) ✅
2. Client has `dataset.query` scope ✅
3. Dataset is `internal`, action is `read` ✅

**Result:** ALLOWED

### Example 2: User Writing to Internal Dataset

**JWT Claims:**
```json
{
  "sub": "user-456",
  "realm_access": {"roles": ["editors"]},
  "scope": "openid dataset.query"
}
```

**Policy Check:**
1. User is in `editors` group (level 2) ✅
2. Client has `dataset.query` scope (not `dataset.admin`) ❌

**Result:** DENIED — "missing dataset.admin scope for write"

### Example 3: Service Accessing Dataset

**JWT Claims (client credentials):**
```json
{
  "client_id": "svc-pipelines",
  "scope": "dataset.query dataset.admin"
}
```

**Policy Check:**
1. Subject type is `service`
2. Service has `dataset.admin` scope ✅

**Result:** ALLOWED

### Example 4: Low-Privilege Client with Admin User

**JWT Claims:**
```json
{
  "sub": "admin-user",
  "realm_access": {"roles": ["admins"]},
  "scope": "openid dataset.query"
}
```

**Request:** Write to restricted dataset

**Policy Check:**
1. User is in `admins` group (level 4) ✅
2. Client has `dataset.query` scope (not `dataset.admin`) ❌

**Result:** DENIED — Client scope limits what the user can do through this application.

---

## Best Practices

### For Service Developers

1. **Request minimal scopes** — Only request what your service actually needs
2. **Use service accounts** — For backend services, use client credentials flow
3. **Don't share clients** — Each service should have its own OAuth client
4. **Rotate secrets** — Regularly rotate client secrets

### For Platform Administrators

1. **Audit scope usage** — Review which clients use which scopes
2. **Principle of least privilege** — Don't grant unnecessary scopes
3. **Separate environments** — Different clients for dev/staging/prod
4. **Monitor denials** — Track authorization failures for anomalies

### Scope Naming Convention

```
{resource}.{action}
```

Examples:
- `dataset.query` — Query (read) datasets
- `dataset.admin` — Administer (full control) datasets
- `dt.read` — Read digital twins
- `mqtt.write` — Write (publish) to MQTT

---

## Troubleshooting

### "missing scope" Error

The calling client doesn't have the required scope.

**Solution:** Add the scope to the client in Keycloak.

### "insufficient group privileges" Error

The user isn't in a high enough group.

**Solution:** Add the user to the appropriate group in Keycloak.

### Service Account Can't Authenticate

The client doesn't have service accounts enabled.

**Solution:** Enable "Service Accounts Enabled" in Keycloak client settings.

### Scope Not in Token

The scope was added to the client but isn't appearing in tokens.

**Checklist:**
1. Is the scope in "Default Client Scopes" or "Optional Client Scopes"?
2. Is "Include in Token Scope" enabled on the client scope?
3. Is the scope being requested in the token request?
