# Architecture

This document describes the authorization model, system architecture, and design decisions of the CELINE Policy Service.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CELINE Platform                                  │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │ digital-twin│  │  pipelines  │  │ rec-registry│  │   nudging   │    │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘    │
│         │                │                │                │            │
│         └────────────────┴────────────────┴────────────────┘            │
│                                   │                                      │
│                                   ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                      Policy Service                                │  │
│  │                                                                    │  │
│  │   ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐    │  │
│  │   │ JWT Validate│──▶│  Subject    │──▶│   OPA Engine        │    │  │
│  │   │ (JWKS cache)│   │  Extract    │   │   (regorus)         │    │  │
│  │   └─────────────┘   └─────────────┘   └──────────┬──────────┘    │  │
│  │                                                   │               │  │
│  │   ┌─────────────┐   ┌─────────────┐              │               │  │
│  │   │ Audit Log   │◀──│  Decision   │◀─────────────┘               │  │
│  │   │ (structured)│   │  Cache      │                              │  │
│  │   └─────────────┘   └─────────────┘                              │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                   │                                      │
│                                   ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                       Keycloak (IdP)                               │  │
│  │   Users, Groups, Service Accounts, OAuth Clients, Scopes          │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Authorization Model

### The Dual-Check Model

The CELINE authorization model enforces **two independent checks** that must both pass:

```
                    ┌─────────────────────────────────────┐
                    │          Authorization              │
                    │                                     │
                    │   ┌───────────┐   ┌───────────┐    │
                    │   │   User    │   │  Client   │    │
                    │   │  Groups   │   │  Scopes   │    │
                    │   │ (roles)   │   │  (OAuth)  │    │
                    │   └─────┬─────┘   └─────┬─────┘    │
                    │         │               │          │
                    │         └───────┬───────┘          │
                    │                 │                  │
                    │                 ▼                  │
                    │         ┌───────────────┐         │
                    │         │  INTERSECTION │         │
                    │         │   (both must  │         │
                    │         │    pass)      │         │
                    │         └───────────────┘         │
                    └─────────────────────────────────────┘
```

**Why this model?**

1. **User Groups** define what a human user is allowed to do (based on their role)
2. **Client Scopes** define what the requesting application is allowed to do

The intersection prevents privilege escalation: even if a user is an admin, a low-privilege client (like a public dashboard) cannot access admin-only resources.

### Subject Types

| Type | Identification | Authorization Source |
|------|----------------|---------------------|
| **User** | JWT `sub` claim | Group hierarchy + Client scopes |
| **Service** | JWT `client_id` claim (no `sub`) | Client scopes only |
| **Anonymous** | No JWT provided | Limited to open resources |

### Group Hierarchy

Users are assigned to groups in Keycloak. Groups have a hierarchy:

```
admins    (level 4) ─── Full platform access
    │
managers  (level 3) ─── Operational access, simulations
    │
editors   (level 2) ─── Write access to non-restricted resources
    │
viewers   (level 1) ─── Read-only access to internal resources
    │
(none)    (level 0) ─── Anonymous / no group membership
```

Higher levels inherit all permissions of lower levels.

### Resource Types

| Resource | Policy Package | Description |
|----------|---------------|-------------|
| `dataset` | `celine.dataset.access` | Data access control with row-level filtering |
| `pipeline` | `celine.pipeline.state` | Pipeline state machine transitions |
| `dt` | `celine.dt.access` | Digital twin API access |
| `topic` | `celine.mqtt.acl` | MQTT topic publish/subscribe |
| `userdata` | `celine.userdata.access` | User-owned resources |

## Policy Engine

### Why OPA?

[Open Policy Agent](https://www.openpolicyagent.org/) provides:

- **Declarative policies** — Rules expressed in Rego, not code
- **Testable** — Policies can be unit tested with `opa test`
- **Decoupled** — Policy changes don't require service redeployment
- **Industry standard** — CNCF graduated project, widely adopted

### Embedded vs. Sidecar

The policy service uses **embedded OPA** (via regorus, a Rust implementation):

| Approach | Latency | Deployment | Best For |
|----------|---------|------------|----------|
| **Embedded** (current) | ~0.1-0.5ms | Single service | Centralized, moderate scale |
| **Sidecar per service** | ~0.1ms | Container per service | High throughput, low latency |
| **Remote OPA** | ~1-5ms | Separate deployment | Shared policies, simple services |

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

All policies receive a standardized input:

```json
{
  "subject": {
    "id": "user-123",
    "type": "user",
    "groups": ["viewers", "editors"],
    "scopes": ["dataset.query", "dt.read"],
    "claims": { /* raw JWT claims */ }
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

```
Incoming Request
       │
       ▼
┌─────────────────┐
│ Extract Bearer  │
│ token from      │
│ Authorization   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│ Fetch JWKS      │◀───▶│ JWKS Cache      │
│ (if needed)     │     │ (1 hour TTL)    │
└────────┬────────┘     └─────────────────┘
         │
         ▼
┌─────────────────┐
│ Validate JWT    │
│ - signature     │
│ - expiry        │
│ - issuer        │
└────────┬────────┘
         │
         ▼
   Valid Claims
```

### 2. Subject Extraction

```python
# Simplified logic
def extract_subject(claims: dict) -> Subject:
    # Service account detection
    if "client_id" in claims and "sub" not in claims:
        return Subject(
            type="service",
            id=claims["client_id"],
            scopes=claims.get("scope", "").split(),
        )
    
    # User detection
    return Subject(
        type="user",
        id=claims["sub"],
        groups=extract_groups(claims),  # From realm_access.roles + groups
        scopes=claims.get("scope", "").split(),
    )
```

### 3. Policy Evaluation

```
Subject + Resource + Action
           │
           ▼
┌──────────────────────┐
│ Check Decision Cache │
└──────────┬───────────┘
           │
     ┌─────┴─────┐
     │  Cache    │
     │  Hit?     │
     └─────┬─────┘
       No  │  Yes
           │    └──────▶ Return Cached Decision
           ▼
┌──────────────────────┐
│ Build Policy Input   │
│ (JSON document)      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ OPA Evaluate         │
│ "data.celine.{type}" │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Cache Decision       │
│ (LRU + TTL)          │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ Audit Log            │
│ (structured JSON)    │
└──────────┬───────────┘
           │
           ▼
      Return Decision
```

## Caching Strategy

### Decision Cache

Identical requests return cached decisions:

| Setting | Default | Description |
|---------|---------|-------------|
| `DECISION_CACHE_ENABLED` | `true` | Enable/disable caching |
| `DECISION_CACHE_TTL_SECONDS` | `300` | Time-to-live for cached decisions |
| `DECISION_CACHE_MAXSIZE` | `10000` | Maximum cache entries |

Cache key: `hash(policy_package + policy_input)`

### JWKS Cache

Public keys are cached to avoid fetching on every request:

| Setting | Default | Description |
|---------|---------|-------------|
| `JWKS_CACHE_TTL_SECONDS` | `3600` | Key cache TTL |

Automatic refresh on:
- TTL expiry
- Unknown key ID (kid) in token

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

### Zero Trust Compliance

| Principle | Implementation |
|-----------|----------------|
| Never trust, always verify | Every request requires valid JWT |
| Least privilege | Scopes limit what each client can do |
| Assume breach | Service-to-service requires auth |
| Defense in depth | User groups + Client scopes |

### Token Security

- JWTs validated with RS256 signatures
- Issuer (`iss`) claim verified against Keycloak
- Expiry (`exp`) enforced
- No token storage — stateless validation

### Recommendations for Production

1. **mTLS** between services and policy service
2. **Network segmentation** — policy service not publicly accessible
3. **Audit log forwarding** to SIEM
4. **Rate limiting** on policy endpoints
5. **Secret rotation** for OAuth clients

## Performance Characteristics

| Metric | Typical Value |
|--------|---------------|
| Policy evaluation | 0.1 - 0.5 ms |
| JWT validation (cached JWKS) | 0.5 - 1 ms |
| Full request (uncached) | 2 - 5 ms |
| Full request (cached) | < 1 ms |
| Throughput | 5,000+ req/sec (single instance) |

## Future Considerations

### Scaling Options

1. **Horizontal scaling** — Multiple policy service instances behind load balancer
2. **OPA sidecars** — Deploy OPA alongside high-throughput services
3. **Policy bundles** — Central service serves bundles to distributed OPA instances

### Potential Enhancements

- GraphQL authorization integration
- Relationship-based access control (ReBAC) for complex hierarchies
- Policy versioning and rollback
- A/B testing for policy changes
