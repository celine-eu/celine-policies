# CELINE Policy Service

Centralized authorization service for the CELINE platform using embedded OPA (Open Policy Agent).

The policy service provides a unified authorization layer for all CELINE platform services, enforcing consistent access control across datasets, pipelines, digital twins, MQTT messaging, and user data.

## Key Features

- **Unified Authorization** — Single service handles all authorization decisions
- **Policy as Code** — Rego policies are versioned, testable, and auditable
- **Zero Trust Model** — Every request is validated regardless of origin
- **Dual Authorization** — User permissions intersected with client scopes
- **MQTT Integration** — Native support for mosquitto-go-auth
- **Audit Logging** — All decisions logged for compliance and debugging

## Quick Start

```bash
# Start the service stack
docker compose up -d

# Verify health
curl http://localhost:8009/health

# Check authorization (requires JWT)
curl -X POST http://localhost:8009/authorize \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{
    "resource": {"type": "dataset", "id": "ds-123", "attributes": {"access_level": "internal"}},
    "action": {"name": "read"}
  }'
```

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Developer quickstart guide |
| [Architecture](docs/architecture.md) | Authorization model and system design |
| [API Reference](docs/api-reference.md) | Complete endpoint documentation |
| [Scopes & Permissions](docs/scopes-and-permissions.md) | OAuth scopes and access control |
| [MQTT Integration](docs/mqtt-integration.md) | Topic patterns and broker setup |
| [Deployment](docs/deployment.md) | Configuration and production deployment |

## Platform Services

The policy service authorizes requests for the following CELINE services:

| Service | Description | Key Scopes |
|---------|-------------|------------|
| **digital-twin** | Digital twin state and simulation | `dt.read`, `dt.write`, `dt.simulate` |
| **pipelines** | Data pipeline orchestration | `pipeline.execute`, `dataset.admin` |
| **rec-registry** | REC certificate registry | `dataset.query`, `dataset.admin` |
| **nudging** | User engagement and notifications | `dt.read`, `userdata.read` |

## Authorization Model Overview

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Client     │────▶│  Policy Service  │────▶│  OPA (regorus)  │
│  (with JWT)  │     │                  │     │                 │
└──────────────┘     └──────────────────┘     └─────────────────┘
                              │
                     ┌────────┴────────┐
                     ▼                 ▼
              ┌────────────┐    ┌────────────┐
              │ User Groups│    │Client Scope│
              │  (roles)   │    │ (OAuth)    │
              └────────────┘    └────────────┘
                     │                 │
                     └────────┬────────┘
                              ▼
                     ┌────────────────┐
                     │   Decision:    │
                     │ groups ∩ scope │
                     └────────────────┘
```

Authorization requires **both**:
1. **User** must have sufficient group level (admins > managers > editors > viewers)
2. **Client** must have the required OAuth scope

This dual-check prevents privilege escalation via low-trust clients.

## Project Structure

```
celine-policies/
├── src/celine/policies/    # Python service code
│   ├── api/                # Policy API layer
│   ├── auth/               # JWT validation, subject extraction
│   ├── engine/             # OPA engine wrapper
│   ├── routes/             # FastAPI endpoints
│   └── models/             # Pydantic models
├── policies/               # Rego policy files
│   └── celine/
│       ├── common/         # Shared helpers
│       ├── dataset/        # Dataset access policies
│       ├── pipeline/       # Pipeline state machine
│       ├── dt/             # Digital twin policies
│       ├── mqtt/           # MQTT ACL policies
│       └── userdata/       # User data access
├── docs/                   # Documentation
├── tests/                  # Python and Rego tests
└── config/                 # Keycloak, mosquitto configs
```

## Development

```bash
# Install dependencies
uv sync

# Run tests
pytest
opa test policies/ -v

# Start development server
uv run uvicorn celine.policies.main:create_app --reload --port 8009
```

## License


Copyright 2026 Spindox Labs

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
