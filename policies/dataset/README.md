# CELINE OPA Policies

Centralized Open Policy Agent (OPA) authorization policies for the CELINE platform.

This repository contains **authorization logic only**.
Authentication, token validation, and request normalization are handled by the calling services.

---

## Scope

- Dataset access authorization
- Shared policy logic across services
- Explicit, auditable access decisions

Out of scope:
- Authentication
- Identity provisioning
- Token issuance (Keycloak, etc.)

---

## Services using these policies

- Dataset API
- (future) Ingestion pipelines
- (future) Admin / governance APIs

---

## Policy model (high level)

Dataset access is governed by **two orthogonal dimensions**:

### 1. Dataset access level

| Level | Meaning |
|------|--------|
| `open` | Publicly accessible |
| `internal` | Limited to trusted operators |
| `restricted` | Highly sensitive, admin-level access only |

### 2. Subject access model

Access is evaluated differently depending on **how the caller authenticates**:

- **Human users** → group-based authorization
- **Service clients** → scope-based authorization

See `docs/policy_model.md` for full details.

---

## OPA input contract

```json
{
  "dataset": {
    "id": "dataset_id",
    "access_level": "open | internal | restricted"
  },
  "subject": {
    "id": "principal-id",
    "groups": ["operators", "managers", "admins"],
    "scopes": ["dataset.query", "dataset.admin"]
  }
}
```

Notes:
- `subject` may be `null` for anonymous access
- `groups` apply to **human users**
- `scopes` apply to **service clients**
- Human users MUST NOT rely on scopes
- Service clients MUST NOT rely on groups

---

## Quick start

```bash
task opa:run
```

```bash
curl -X POST http://localhost:8181/v1/data/celine/dataset/access/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "dataset": {
        "access_level": "internal"
      },
      "subject": {
        "id": "dt-forecast-engine",
        "scopes": ["dataset.query"],
        "groups": []
      }
    }
  }'
```

---

## Run tests

```bash
task test
```

---

## Philosophy

- Policies are pure logic
- OAuth/OIDC-aligned
- Fail-closed by default
- Strong test coverage
- Versioned and auditable
