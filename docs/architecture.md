# Architecture

This document describes the components, authorization model, and design of the celine-policies repository.

## Components

The repository contains three main pieces:

### 1. MQTT Auth Service

A FastAPI application (`src/celine/mqtt_auth/`) that acts as the HTTP backend for [mosquitto-go-auth](https://github.com/iegomez/mosquitto-go-auth). Mosquitto delegates authentication and authorization decisions to this service over HTTP.

The service uses `celine-sdk`'s `PolicyEngine` (built on [regorus](https://github.com/nicholasgasior/regorus), a Rust OPA implementation) to evaluate Rego policies at request time. An optional in-memory decision cache (`CachedPolicyEngine`) reduces repeated evaluations.

**Endpoints:** `/user` (auth), `/acl` (topic access), `/superuser` (admin check), `/health`.

### 2. Keycloak CLI

A typer CLI (`src/celine/policies/cli/`) that manages Keycloak configuration. It reads `clients.yaml` — which defines all platform OAuth scopes and service clients — and idempotently provisions them in Keycloak.

**Commands:**
- `bootstrap` — create a `celine-admin-cli` service account with realm-management roles
- `sync` — reconcile scopes and clients in Keycloak to match `clients.yaml`
- `sync-users` — create Keycloak users from a `rec-registry` REC definition YAML
- `sync-orgs` — create Keycloak organizations from an `owners.yaml`
- `set-password` — set a user's password
- `set-user-organization` — assign a user to organizations and org-level groups
- `status` — show current scopes, clients, and assignments

Authentication to Keycloak uses either admin user credentials (`--admin-user`) or a service account client (`celine-admin-cli`) whose secret is stored in `.client.secrets.yaml` after bootstrap.

### 3. Rego Policies

Two policy files under `policies/celine/`:

- **`scopes.rego`** — shared helpers for checking subject type (user vs service), scope membership, group membership, and admin detection. Supports multiple group naming conventions (`service.resource.verb`, `mqtt:service:resource:verb`, wildcards).

- **`mqtt/acl.rego`** — MQTT topic ACL rules. Parses topics following the `celine/{service}/{resource}/{...}` convention and decides allow/deny based on:
  - Service admin scopes (e.g. `digital-twin.admin`)
  - User admin groups (`admin`, `mqtt.admin`, `{service}.admin`)
  - Fine-grained scopes/groups matching `{service}.{resource}.{verb}`

## MQTT Authorization Flow

```
MQTT Client ──(JWT as password)──> Mosquitto
                                      │
                               mosquitto-go-auth
                                      │
                          ┌───────────┼───────────┐
                          │           │           │
                      /user       /acl      /superuser
                          │           │           │
                     JWT valid?   OPA eval    admin scope?
                          │           │           │
                        200/403    200/403     200/403
```

1. Client connects to Mosquitto with a JWT (obtained from Keycloak) as the MQTT password.
2. Mosquitto calls `/user` — the service validates the JWT signature, issuer, and expiry.
3. On publish/subscribe, Mosquitto calls `/acl` — the service builds a `PolicyInput` from the JWT claims (subject, scopes, groups) and the requested topic/action, then evaluates `celine.mqtt.acl` via regorus.
4. Optionally, `/superuser` is checked — grants bypass if the JWT carries `mqtt.admin` scope or `admin` group.

## Keycloak Sync Flow

```
clients.yaml ──> celine-policies keycloak sync ──> Keycloak Admin API
                       │
                 compute diff
                 (scopes to create/update,
                  clients to create/update,
                  scope assignments,
                  audience mappers)
                       │
                 apply changes
                       │
                 .client.secrets.yaml
```

The `sync` command:
1. Loads `clients.yaml` (scopes + clients with `default_scopes` and `scopes_prefix`)
2. Fetches current state from Keycloak (existing scopes, clients, assignments)
3. Computes a diff (plan): scopes to create/update, clients to create/update, scope assignments to add/remove
4. Applies changes idempotently
5. Writes generated client secrets to `.client.secrets.yaml`

The `scopes_prefix` field on each client declares scope ownership. The CLI uses this to automatically add audience mappers so that user JWTs issued through `oauth2-proxy` carry the correct audience for each service.

## Topic Naming Convention

MQTT topics follow the pattern:

```
celine/{service}/{resource}/{...}
```

The ACL policy derives the required scope as `{service}.{resource}.{verb}` (where verb is `read` for subscribe/read, `write` for publish).

Examples:
- `celine/pipelines/runs/pipeline-123` → requires `pipelines.runs.read` (subscribe) or `pipelines.runs.write` (publish)
- `celine/digital-twin/events/pump/pump-001` → requires `digital-twin.events.read` or `digital-twin.events.write`

Service-level wildcards (`celine/{service}/#`) require service admin access.

## Subject Types

| Type | Identification | Authorization |
|---|---|---|
| User | JWT has groups | Group-based access (via `scopes.rego` helpers) |
| Service | JWT has scopes but no groups | Scope-based access |
| Anonymous | No valid JWT | Denied |

## Configuration

The MQTT auth service is configured via environment variables with the `CELINE_` prefix (see `MqttAuthSettings`):

| Variable | Default | Description |
|----------|---------|-------------|
| `CELINE_OIDC_*` | (from celine-sdk) | OIDC/JWT validation settings |
| `CELINE_POLICIES_DIR` | `./policies` | Path to Rego policy files |
| `CELINE_POLICIES_DATA_DIR` | `None` | Path to policy data JSON files |
| `CELINE_POLICIES_CACHE_ENABLED` | `true` | Enable decision caching |
| `CELINE_POLICIES_CACHE_TTL` | `300` | Cache TTL in seconds |
| `CELINE_POLICIES_CACHE_MAXSIZE` | `10000` | Max cache entries |
| `CELINE_MQTT_POLICY_PACKAGE` | `celine.mqtt.acl` | Rego package to evaluate |
| `CELINE_MQTT_SUPERUSER_SCOPE` | `mqtt.admin` | Scope for superuser access |

The Keycloak CLI is configured via `CELINE_KEYCLOAK_*` environment variables (see `KeycloakSettings`):

| Variable | Default | Description |
|----------|---------|-------------|
| `CELINE_KEYCLOAK_BASE_URL` | `http://keycloak.celine.localhost` | Keycloak URL |
| `CELINE_KEYCLOAK_REALM` | `celine` | Target realm |
| `CELINE_KEYCLOAK_ADMIN_USER` | — | Admin username (for bootstrap) |
| `CELINE_KEYCLOAK_ADMIN_PASSWORD` | — | Admin password (for bootstrap) |
| `CELINE_KEYCLOAK_ADMIN_CLIENT_ID` | `celine-admin-cli` | Service client ID |
| `CELINE_KEYCLOAK_ADMIN_CLIENT_SECRET` | — | Service client secret |
| `CELINE_KEYCLOAK_SECRETS_FILE` | `.client.secrets.yaml` | Auto-load secret from file |
