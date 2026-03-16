# Architecture

This document describes the authorization model, system architecture, and design decisions of the CELINE Policy Service.

## System Overview

The CELINE platform services (digital-twin, pipelines, rec-registry, nudging) delegate all authorization decisions to the Policy Service. The Policy Service validates the JWT, extracts the subject, evaluates Rego policies in an embedded OPA engine, and returns an allow/deny decision with optional row-level filters. Keycloak is the identity provider that issues the JWTs.

## Authorization Model

### The Dual-Check Model

The CELINE authorization model enforces **two independent checks** that must both pass:

| Check | Source | Description |
|---|---|---|
| User groups | JWT `groups` or `realm_access.roles` claim | Role hierarchy: admins > managers > editors > viewers |
| Client scopes | JWT `scope` claim | OAuth scopes granted to the calling service client |

**Why this model?**

1. **User Groups** define what a human user is allowed to do based on their role.
2. **Client Scopes** define what the requesting application is allowed to do.

The intersection prevents privilege escalation: even if a user is an admin, a low-privilege client (like a public dashboard) cannot access admin-only resources.

### Subject Types

| Type | Identification | Authorization Source |
|---|---|---|
| User | JWT `sub` claim present | Group hierarchy + Client scopes |
| Service | JWT `client_id` claim, no `sub` | Client scopes only |
| Anonymous | No JWT provided | Limited to open resources |

### Group Hierarchy

Users are assigned to groups in Keycloak. Groups have a hierarchy with level inheritance:

| Group | Level | Access |
|---|---|---|
| admins | 4 | Full platform access |
| managers | 3 | Operational access, simulations |
| editors | 2 | Write access to non-restricted resources |
| viewers | 1 | Read-only access to internal resources |
| (none) | 0 | Anonymous / no group membership |

Higher levels inherit all permissions of lower levels.

### Resource Types

| Resource | Policy Package | Description |
|---|---|---|
| `dataset` | `celine.dataset.access` | Data access control with row-level filtering |
| `pipeline` | `celine.pipeline.state` | Pipeline state machine transitions |
| `dt` | `celine.dt.access` | Digital twin API access |
| `topic` | `celine.mqtt.acl` | MQTT topic publish/subscribe |
| `userdata` | `celine.userdata.access` | User-owned resources |

## Policy Engine

### Why OPA?

[Open Policy Agent](https://www.openpolicyagent.org/) provides declarative, testable, decoupled policies in Rego. It is a CNCF graduated project widely adopted for authorization use cases.

### Embedded vs. Sidecar

The policy service uses **embedded OPA** (via regorus, a Rust implementation):

| Approach | Latency | Deployment | Best For |
|---|---|---|---|
| Embedded (current) | ~0.1-0.5ms | Single service | Centralized, moderate scale |
| Sidecar per service | ~0.1ms | Container per service | High throughput, low latency |
| Remote OPA | ~1-5ms | Separate deployment | Shared policies, simple services |

For high-throughput services, the architecture can evolve to sidecars that pull policy bundles from this central service.

### Policy Packages

```
policies/celine/
├── common/
│   ├── subject.rego      # is_user, is_service, has_scope(), in_group()
│   └── access_levels.rego # level_value(), is_open(), etc.
├── dataset/
│   ├── access.rego       # allow, reason, filters
│   ├── row_filter.rego   # Row-level security filters
│   └── access_test.rego  # Policy unit tests
├── pipeline/
│   └── state.rego        # State machine validation
├── dt/
│   └── access.rego       # Digital twin access
├── mqtt/
│   └── acl.rego          # Topic ACLs
└── userdata/
    └── access.rego       # User data ownership
```

### Policy Input Structure

All policies receive a standardized input document:

```json
{
  "subject": {
    "id": "user-123",
    "type": "user",
    "groups": ["viewers", "editors"],
    "scopes": ["dataset.query", "dt.read"],
    "claims": {}
  },
  "resource": {
    "type": "dataset",
    "id": "ds-456",
    "attributes": {
      "access_level": "internal"
    }
  },
  "action": {
    "name": "read",
    "context": {}
  },
  "environment": {
    "request_id": "req-789",
    "timestamp": 1706745600
  }
}
```

### Policy Output Structure

```json
{
  "allow": true,
  "reason": "user has viewer access and client has dataset.query scope",
  "filters": [
    {"field": "organization_id", "operator": "eq", "value": "org-123"}
  ]
}
```

## Request Flow

### 1. JWT Validation

1. Extract the Bearer token from the `Authorization` header.
2. Look up the signing key from the JWKS cache (fetch from Keycloak if expired or unknown kid).
3. Validate JWT signature (RS256), expiry (`exp`), and issuer (`iss`).
4. Return validated claims or reject with 401.

### 2. Subject Extraction

```python
# Simplified logic
def extract_subject(claims: dict) -> Subject:
    if "client_id" in claims and "sub" not in claims:
        return Subject(
            type="service",
            id=claims["client_id"],
            scopes=claims.get("scope", "").split(),
        )
    return Subject(
        type="user",
        id=claims["sub"],
        groups=extract_groups(claims),
        scopes=claims.get("scope", "").split(),
    )
```

### 3. Policy Evaluation

1. Check the LRU decision cache using a hash of (policy_package + policy_input).
2. On cache miss: build the policy input document and evaluate with OPA (regorus).
3. Cache the decision with TTL.
4. Write a structured audit log entry.
5. Return the decision to the caller.

## Caching Strategy

### Decision Cache

| Setting | Default | Description |
|---|---|---|
| `DECISION_CACHE_ENABLED` | `true` | Enable/disable caching |
| `DECISION_CACHE_TTL_SECONDS` | `300` | Time-to-live for cached decisions |
| `DECISION_CACHE_MAXSIZE` | `10000` | Maximum cache entries |

Cache key: `hash(policy_package + policy_input)`

### JWKS Cache

| Setting | Default | Description |
|---|---|---|
| `JWKS_CACHE_TTL_SECONDS` | `3600` | Key cache TTL |

The JWKS is automatically refreshed on TTL expiry or when an unknown key ID (`kid`) appears in a token.

## Audit Logging

All decisions are logged with structured JSON:

```json
{
  "timestamp": "2024-01-31T12:00:00Z",
  "event": "policy_decision",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "allowed": true,
  "policy": "celine.dataset.access",
  "subject_id": "user-123",
  "subject_type": "user",
  "resource_type": "dataset",
  "resource_id": "ds-456",
  "action": "read",
  "source_service": "digital-twin",
  "latency_ms": 0.42,
  "cached": false
}
```

## Security Considerations

| Principle | Implementation |
|---|---|
| Never trust, always verify | Every request requires a valid JWT |
| Least privilege | Scopes limit what each client can do |
| Assume breach | Service-to-service requires auth |
| Defense in depth | User groups AND client scopes both required |

**Token security:** JWTs validated with RS256 signatures. Issuer (`iss`) verified against Keycloak. Expiry (`exp`) enforced. No token storage — stateless validation.

## Performance Characteristics

| Metric | Typical Value |
|---|---|
| Policy evaluation | 0.1 – 0.5 ms |
| JWT validation (cached JWKS) | 0.5 – 1 ms |
| Full request (uncached) | 2 – 5 ms |
| Full request (cached) | < 1 ms |
| Throughput | 5,000+ req/sec (single instance) |
