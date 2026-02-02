# CELINE Policy Service Architecture Guide

## Executive Summary

This document explains how the CELINE policy system works, how services should interface with the API, recommendations for OAuth client configuration across your services, and MQTT topic pattern conventions.

---

## Industry Best Practices

This section summarizes key industry standards and best practices that validate and inform the CELINE architecture decisions.

### OAuth2 for Microservices

**Consensus from industry sources:**

1. **Separate OAuth clients per service** (Principle of Least Privilege)
   - Each microservice should have its own OAuth2 client with scopes tailored to its specific needs
   - This enables granular revocation, independent secret rotation, and clear audit trails
   - Services use the **client_credentials** grant for service-to-service communication

2. **Centralized Authentication, Decentralized Authorization**
   - Authentication should be centralized at an Identity Provider (Keycloak, Okta, Auth0)
   - Authorization decisions should happen at the edge of each microservice (Zero Trust)
   - Your architecture correctly follows this: JWT validation + OPA policy evaluation per request

3. **JWT for User Context Propagation**
   - JWTs carry user identity and claims across service boundaries cryptographically
   - Each service validates the JWT independently (don't trust the network)
   - Your dual-check model (user groups ∩ client scopes) is a best practice

**Reference Architecture:**
```
User → API Gateway → [JWT issued] → Service A → [JWT forwarded] → Service B
                                         ↓                            ↓
                                   Policy Check               Policy Check
                                   (OPA/local)                (OPA/local)
```

### Zero Trust for Microservices

**Core Principles (NIST SP 800-207, industry consensus):**

| Principle | Implementation in CELINE |
|-----------|-------------------------|
| **Never trust, always verify** | Every request validated via JWT + OPA policy |
| **Least privilege** | Scopes restrict what each client can do |
| **Assume breach** | Service-to-service auth required, not implicit trust |
| **Verify explicitly** | Policy service checks both identity AND authorization |

**Recommended Enhancements:**
- Consider **mTLS** for service-to-service communication (transport layer)
- Your current JWT-based approach handles application layer well
- Log all policy decisions (you already do this via audit logging ✓)

### OPA (Open Policy Agent) Best Practices

Your use of embedded OPA (regorus) aligns with CNCF recommendations:

1. **Policy as Code** ✓
   - Rego policies versioned in Git
   - Testable with `opa test`
   - Hot-reloadable via `/reload` endpoint

2. **Decoupled Policy from Enforcement** ✓
   - Services call policy service for decisions
   - Business logic remains separate from auth logic

3. **Centralized Policy, Distributed Enforcement**
   - Single policy service evaluates all decisions
   - Consider: For very high throughput, OPA sidecars per service can reduce latency

4. **Test Policies Like Code** ✓
   - You have `*_test.rego` files for each policy package
   - Integrate `opa test` in CI/CD pipeline

**OPA Deployment Patterns:**

| Pattern | Latency | Consistency | Your Fit |
|---------|---------|-------------|----------|
| Centralized (current) | ~1-5ms network | High | Good for moderate scale |
| Sidecar per service | ~0.1-0.5ms | Requires sync | High throughput needs |
| Embedded in service | Lowest | Requires bundling | Per-service customization |

### MQTT Authorization Best Practices

**Industry standards (HiveMQ, EMQX, Mosquitto):**

1. **Principle of Least Privilege for Topics**
   - Devices/services should only access topics they need
   - Use topic patterns with client ID or service name: `celine/{service}/...`
   - Your proposed pattern `celine/[service]/[specific]` follows this ✓

2. **Topic Hierarchy for ACL Efficiency**
   ```
   celine/
   ├── {service}/           # Service-owned topics
   │   ├── events/...       # Published events
   │   └── commands/...     # Received commands
   └── shared/              # Cross-service topics (restricted)
   ```

3. **Common ACL Patterns:**
   - **Client ID in topic**: `pattern readwrite %c/#` (client can only pub/sub to topics starting with their ID)
   - **Service-scoped access**: Services with `mqtt.write` can publish to their namespace
   - **Wildcard caution**: Avoid granting `#` access except for admin/superuser

4. **JWT-based MQTT Authentication** ✓
   - Pass JWT as username or password field (you do this)
   - Validate JWT on connect AND on pub/sub operations
   - Token expiry should disconnect client

### Scope Naming Conventions

**Industry patterns:**

| Pattern | Example | Use Case |
|---------|---------|----------|
| `resource.action` | `dataset.read`, `dataset.write` | Fine-grained control |
| `resource.level` | `dataset.query`, `dataset.admin` | Tiered access |
| `service.capability` | `mqtt.publish`, `mqtt.subscribe` | Protocol-specific |

Your current scopes follow the `resource.action` pattern, which is well-established.

**Recommendation:** Consider adding a `service:` prefix for service-specific scopes if you want to distinguish them from user-facing scopes:
- `service:pipeline.execute` (service-to-service)
- `user:dataset.query` (user-facing client)

### Summary: Your Architecture vs Best Practices

| Best Practice | CELINE Status |
|--------------|---------------|
| Centralized IdP (Keycloak) | ✅ Implemented |
| JWT for identity propagation | ✅ Implemented |
| Policy engine (OPA/Rego) | ✅ Implemented |
| Per-service OAuth clients | 🔧 Recommended (implement) |
| Least privilege scopes | ✅ Designed |
| Zero Trust (verify every request) | ✅ Implemented |
| MQTT topic namespacing | 🔧 Recommended (implement) |
| Policy testing | ✅ Implemented |
| Audit logging | ✅ Implemented |
| mTLS for transport | ⚪ Optional enhancement |

---

## 1. How Policies Work

### 1.1 Architecture Overview

The policy service uses **embedded OPA (via regorus)** to evaluate authorization decisions. The core flow is:

```
Service Request → Policy Service API → JWT Validation → Subject Extraction → OPA Evaluation → Decision
```

### 1.2 Subject Model

The system recognizes two principal types:

| Type | Identified By | Authorization Mechanism |
|------|---------------|------------------------|
| **User** | JWT `sub` claim | Group hierarchy (`admins` > `managers` > `editors` > `viewers`) intersected with client scopes |
| **Service** | JWT `client_id` claim | OAuth scopes only |

**Key insight**: For user tokens, authorization requires **both** the user to have sufficient group level **AND** the calling client to have the required scope. This is intentional—it prevents a low-privilege client from being used to access resources the user could access via a more privileged client.

### 1.3 Policy Packages

Each resource type maps to a policy package:

| Resource Type | Policy Package |
|--------------|----------------|
| `dataset` | `celine.dataset.access` |
| `pipeline` | `celine.pipeline.state` |
| `dt` | `celine.dt.access` |
| `topic` (MQTT) | `celine.mqtt.acl` |
| `userdata` | `celine.userdata.access` |

### 1.4 Decision Flow Example

When `digital-twin` service requests dataset access for a user:

1. User authenticates to `digital-twin` via Keycloak, receiving a JWT with:
   - `sub`: user ID
   - `groups`: `["viewers"]`
   - `scope`: `"dt.read dataset.query"` (scopes granted to `digital-twin` client)

2. `digital-twin` calls the policy service with the user's JWT

3. Policy service extracts subject:
   ```python
   Subject(
       id="user-123",
       type="user",
       groups=["viewers"],
       scopes=["dt.read", "dataset.query"]
   )
   ```

4. OPA evaluates `celine.dataset.access`:
   - User has `viewers` group (level 1) ✓
   - Client has `dataset.query` scope ✓
   - Dataset is `internal` + action is `read` ✓
   - **Result: ALLOWED**

---

## 2. Interfacing with the Policy API

### 2.1 Generic Authorization Endpoint

```http
POST /authorize
Authorization: Bearer <jwt>
Content-Type: application/json
X-Request-Id: <optional-correlation-id>
X-Source-Service: <calling-service-name>

{
  "resource": {
    "type": "dataset",
    "id": "ds-123",
    "attributes": {
      "access_level": "internal"
    }
  },
  "action": {
    "name": "read",
    "context": {}
  }
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

### 2.2 Domain-Specific Endpoints

For convenience, domain-specific endpoints exist:

| Endpoint | Purpose |
|----------|---------|
| `POST /dataset/access` | Check dataset access |
| `POST /dataset/filters` | Get row-level filters for queries |
| `POST /pipeline/transition` | Validate state machine transitions |
| `POST /mqtt/user` | MQTT authentication |
| `POST /mqtt/acl` | MQTT topic authorization |
| `POST /mqtt/superuser` | MQTT superuser check |

### 2.3 Integration Pattern for Services

Each service should follow this pattern:

```python
# In your service (e.g., digital-twin)
import httpx

class PolicyClient:
    def __init__(self, policy_service_url: str):
        self.url = policy_service_url
    
    async def check_access(
        self,
        jwt_token: str,
        resource_type: str,
        resource_id: str,
        action: str,
        attributes: dict = None
    ) -> bool:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.url}/authorize",
                headers={
                    "Authorization": f"Bearer {jwt_token}",
                    "X-Source-Service": "digital-twin"
                },
                json={
                    "resource": {
                        "type": resource_type,
                        "id": resource_id,
                        "attributes": attributes or {}
                    },
                    "action": {"name": action}
                }
            )
            return resp.json()["allowed"]
```

---

## 3. OAuth Client Strategy

### 3.1 Recommendation: Separate Clients per Service

**Yes, each service should have its own OAuth client with scopes tailored to its needs.**

This provides:

- **Principle of Least Privilege**: Each service only gets the scopes it actually needs
- **Audit Clarity**: Logs clearly show which service performed which action
- **Revocation Granularity**: Compromised service can be disabled without affecting others
- **Independent Rotation**: Client secrets can be rotated per-service

### 3.2 Proposed Client Configuration

| Service | Client ID | Client Type | Suggested Scopes |
|---------|-----------|-------------|------------------|
| **digital-twin** | `svc-digital-twin` | Confidential | `dt.read`, `dt.write`, `dt.simulate`, `dataset.query`, `mqtt.write` |
| **pipelines** | `svc-pipelines` | Confidential | `pipeline.execute`, `dataset.query`, `dataset.admin`, `mqtt.write` |
| **rec-registry** | `svc-rec-registry` | Confidential | `dataset.query`, `dataset.admin` |
| **nudging** | `svc-nudging` | Confidential | `dt.read`, `userdata.read`, `mqtt.write` |
| **frontend** | `celine-frontend` | Public | `dt.read`, `dataset.query`, `userdata.read`, `userdata.write` |

### 3.3 Keycloak Client Setup

For each service client in Keycloak:

```json
{
  "clientId": "svc-digital-twin",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "serviceAccountsEnabled": true,
  "standardFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "defaultClientScopes": [
    "dt.read",
    "dt.write",
    "dt.simulate",
    "dataset.query",
    "mqtt.write"
  ]
}
```

### 3.4 Scope Definitions

Create these as client scopes in Keycloak:

| Scope | Description | Typical Consumers |
|-------|-------------|-------------------|
| `dataset.query` | Read internal datasets | All services |
| `dataset.admin` | Write all datasets, read restricted | pipelines, rec-registry |
| `dt.read` | Read digital twin data | digital-twin, nudging |
| `dt.write` | Write digital twin data | digital-twin |
| `dt.simulate` | Run simulations | digital-twin |
| `dt.admin` | Full DT control | admin tools |
| `pipeline.execute` | Execute pipeline transitions | pipelines |
| `mqtt.read` | Subscribe/read MQTT topics | subscribers |
| `mqtt.write` | Publish to MQTT topics | publishers |
| `mqtt.admin` | Full MQTT access | admin tools |
| `userdata.read` | Read user data | nudging, frontend |
| `userdata.write` | Modify user data | frontend |
| `userdata.admin` | Admin override for user data | admin tools |

---

## 4. MQTT Topic Patterns

### 4.1 Proposed Topic Structure

Following your suggested pattern `celine/[service-name]/[service-specific-parts]`:

```
celine/
├── digital-twin/
│   ├── events/{entity_type}/{entity_id}     # DT events
│   ├── state/{entity_type}/{entity_id}      # Current state
│   └── simulation/{run_id}/+                # Simulation outputs
├── pipelines/
│   ├── status/{pipeline_id}                 # Pipeline status changes
│   └── events/{pipeline_id}/{event_type}    # Pipeline events
├── rec-registry/
│   └── updates/{rec_type}/{rec_id}          # Registry updates
├── nudging/
│   ├── triggers/{user_id}                   # Nudge triggers
│   └── responses/{user_id}                  # User responses
└── telemetry/
    └── {device_type}/{device_id}/readings   # Raw telemetry
```

### 4.2 ACL Rules Configuration

Update `policies/data/celine.json` to include service-specific rules:

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
              "scopes": ["dt.write"]
            },
            "topics": [
              "celine/digital-twin/events/#",
              "celine/digital-twin/state/#"
            ],
            "actions": ["publish"],
            "effect": "allow"
          },
          {
            "subjects": {
              "types": ["service"],
              "scopes": ["dt.read"]
            },
            "topics": [
              "celine/digital-twin/#"
            ],
            "actions": ["subscribe", "read"],
            "effect": "allow"
          },
          {
            "subjects": {
              "types": ["service"],
              "scopes": ["pipeline.execute"]
            },
            "topics": [
              "celine/pipelines/status/+",
              "celine/pipelines/events/#"
            ],
            "actions": ["publish"],
            "effect": "allow"
          },
          {
            "subjects": {
              "types": ["user"],
              "groups": ["viewers"]
            },
            "topics": [
              "celine/telemetry/+/+/readings"
            ],
            "actions": ["subscribe", "read"],
            "effect": "allow"
          }
        ]
      }
    }
  }
}
```

### 4.3 Topic Pattern Wildcards

The MQTT ACL policy supports standard MQTT wildcards:

- `+` matches exactly one level (e.g., `celine/+/events` matches `celine/dt/events`)
- `#` matches zero or more levels (e.g., `celine/dt/#` matches `celine/dt/state/pump/123`)

---

## 5. Current Implementation Status

Based on the code review:

### ✅ Completed

| Component | Status |
|-----------|--------|
| Policy Engine (regorus) | Working |
| JWT Validation + JWKS caching | Working |
| Subject extraction (user/service) | Working |
| Dataset access policies | Complete with row-level filters |
| Pipeline state machine | Complete |
| Digital Twin access policies | Complete |
| User data policies (ownership, sharing) | Complete |
| MQTT ACL policy framework | Complete |
| Decision caching | Working |
| Audit logging | Working |

### 🚧 In Progress / Needs Work

| Component | Status | Notes |
|-----------|--------|-------|
| MQTT `/acl` endpoint | **Partially implemented** | ACL logic is commented out in `routes/mqtt.py` (lines 4253-4291). Currently returns `ok=True` for all requests. |
| MQTT `/user` endpoint | Working | JWT auth via Bearer token |
| MQTT data file | Minimal | Only has admin rule, needs service-specific rules |
| mosquitto-go-auth config | Configured | Points to policy service |

### 🔧 Required to Complete MQTT

1. **Uncomment ACL logic** in `src/celine/policies/routes/mqtt.py`:
   ```python
   # The commented code at lines 4253-4291 needs to be enabled
   ```

2. **Expand ACL rules** in `policies/data/celine.json` with your topic patterns

3. **Configure mosquitto** to pass JWT in the right format (currently expects JWT in Authorization header or username field)

---

## 6. Quick Reference

### API Endpoints Cheat Sheet

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/authorize` | POST | Bearer JWT | Generic authorization |
| `/dataset/access` | POST | Bearer JWT | Dataset access check |
| `/dataset/filters` | POST | Bearer JWT | Get row-level filters |
| `/pipeline/transition` | POST | Bearer JWT | Validate state change |
| `/mqtt/user` | POST | Bearer JWT | MQTT authentication |
| `/mqtt/acl` | POST | Bearer JWT | MQTT topic authorization |
| `/mqtt/superuser` | POST | Bearer JWT | MQTT superuser check |
| `/health` | GET | None | Liveness |
| `/ready` | GET | None | Readiness |
| `/reload` | POST | None | Hot-reload policies |

### Headers

| Header | Required | Purpose |
|--------|----------|---------|
| `Authorization` | Yes* | `Bearer <JWT>` (*except health endpoints) |
| `X-Request-Id` | No | Correlation ID for tracing |
| `X-Source-Service` | No | Calling service name for audit |

---

## 7. Next Steps

1. **Uncomment MQTT ACL logic** in the routes file
2. **Create Keycloak clients** for each service with appropriate scopes
3. **Expand MQTT ACL rules** with your topic patterns
4. **Test end-to-end** with each service authenticating and publishing/subscribing
5. **Document** the topic conventions for your team

---

## 8. References & Further Reading

### OAuth2 & Microservices Security
- [Microservices.io - Authentication in Microservices](https://microservices.io/post/architecture/2025/05/28/microservices-authn-authz-part-2-authentication.html)
- [Microsoft - Securing .NET Microservices](https://learn.microsoft.com/en-us/dotnet/architecture/microservices/secure-net-microservices-web-applications/)
- [Spring Cloud Gateway with OAuth2 and Keycloak](https://piotrminkowski.com/2024/03/01/microservices-with-spring-cloud-gateway-oauth2-and-keycloak/)

### OPA Best Practices
- [OPA Official Documentation](https://www.openpolicyagent.org/docs/latest/)
- [CNCF - OPA Best Practices for Secure Deployment](https://www.cncf.io/blog/2025/03/18/open-policy-agent-best-practices-for-a-secure-deployment/)
- [Styra - OPA 101 Beginner's Guide](https://www.styra.com/blog/open-policy-agent-101-a-beginners-guide/)
- [Permit.io - Authorization with OPA](https://www.permit.io/blog/authorization-with-open-policy-agent-opa)

### MQTT Security
- [HiveMQ - MQTT Security Fundamentals: Authorization](https://www.hivemq.com/blog/mqtt-security-fundamentals-authorization/)
- [EMQX - Authorization in MQTT Using ACLs](https://www.emqx.com/en/blog/authorization-in-mqtt-using-acls-to-control-access-to-mqtt-messaging)
- [Cirrus Link - Securing MQTT Best Practices](https://cirrus-link.com/securing-mqtt-best-practices-for-a-robust-iot-ecosystem/)
- [Cedalo - MQTT Authentication and Authorization on Mosquitto](https://cedalo.com/blog/mqtt-authentication-and-authorization-on-mosquitto/)

### Zero Trust Architecture
- [WSO2 - Microservices Security in Zero Trust Environment](https://wso2.com/blogs/thesource/securing-microservices-in-a-zero-trust-environment/)
- [Cerbos - Zero Trust for Microservices Blueprint](https://www.cerbos.dev/blog/zero-trust-for-microservices)
- [Kong - Zero Trust OAuth 2.0 mTLS Client Authentication](https://konghq.com/blog/engineering/zero-trust-oauth-2-0-mtls-client-authentication)
