# Architecture

This document describes the components, authorization model, and design of the celine-policies repository.

## Components

The repository contains four main pieces:

### 1. MQTT Auth Service

A FastAPI application (`src/celine/mqtt_auth/`) that acts as the HTTP backend for [mosquitto-go-auth](https://github.com/iegomez/mosquitto-go-auth). Mosquitto delegates authentication and authorization decisions to this service over HTTP.

The service uses `celine-sdk`'s `PolicyEngine` (built on [regorus](https://github.com/nicholasgasior/regorus), a Rust OPA implementation) to evaluate Rego policies at request time. An optional in-memory decision cache (`CachedPolicyEngine`) reduces repeated evaluations.

**Endpoints:** `/user` (auth), `/acl` (topic access), `/superuser` (admin check), `/health`.

### 2. Provisioning Service

A FastAPI application (`src/celine/provisioning/`) that is the **only thing that writes a
participant account** into the celine realm. `keycloak sync-users` calls the same package;
`../onboarding` calls the service and holds no Keycloak grant of its own. It is the
**only** client granted a `provisioning.*` scope: onboarding is the single point of access to
the provisioner.

**Endpoints:** `PUT /participants/{community}/{key}` (ensure the account, its REC
organization and its org group, and optionally invite the person),
`POST /participants/{community}/{key}/invitation` (email an invitation or a password
reset, as the body's `intent` names), `POST /participants/{community}/{key}/disable`,
`POST /reconcile/{community}`, `/health`.

**No password is ever generated, returned or emailed.** Keycloak sends every email, through
`execute-actions-email`, and the person sets their own password from the link. The service
decides only whether to ask for one and for how long it lasts — see
`celine.provisioning.invitation` and the [API reference](api-reference.md#provisioning-service).

It is stateless — a retry is another `PUT`, and idempotency comes from the keys — and it
authorises by `provisioning.*` scopes like every other service.

**It holds realm-wide Keycloak administration** (`manage-users` + `manage-realm`), which is
what makes organization membership possible at all: no fine-grained permission expresses
the Organizations API. The grant is acceptable only because **nothing outside
the network can reach the service**, and that is a property of the ingress configuration
rather than of any code here. See
[ADR-0007](decisions/ADR-0007-realm-wide-administration-is-declared-for-a-holder-with-no-public-route.md).

**It cannot bootstrap the realm it authenticates against.** `keycloak bootstrap` and
`keycloak sync` create the client whose credential it presents, so they run first.

### 3. Keycloak CLI

A typer CLI (`src/celine/policies/cli/`) that manages Keycloak configuration. Each command
owns one level of the realm and checks the levels below it, refusing with the command to
run instead of writing them:

1. **platform** — `platform.yaml`, written by `bootstrap`;
2. **clients** — `clients.yaml`, written by `sync`;
3. **organizations and users** — written by `sync-orgs`, `sync-users` and the provisioning service.

**Commands:**
- `bootstrap` — converge the platform level from `platform.yaml` (only the keys it declares;
  a deployment overlay may narrow `supportedLocales` and nothing else), brute force from
  `CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED`, `smtpServer` from `CELINE_KEYCLOAK_SMTP_*`; then
  create or refresh the `celine-admin-cli` service account with realm-management roles.
  It refuses a theme the server does not list. With the admin CLI client's own credentials
  it converges the platform and skips the client
- `sync` — reconcile scopes, clients, audience mappers, the realm claim scopes and
  service-account administration rights in Keycloak to match `clients.yaml`. It refuses to
  grant `admin_permissions` on a realm where `bootstrap` has not turned them on
- `sync-users` — create Keycloak users from a `rec-registry` REC definition YAML, and
  file them in the groups `clients.yaml` declares a service account may administer.
  `--invite` creates them with no password and invites each account it created in that
  run, under the provisioning service's email settings
- `sync-orgs` — create Keycloak organizations from an `owners.yaml`
- `sync-orgs` and `sync-users` refuse a realm without Organizations (`bootstrap`) or without
  the realm claim scopes (`sync`), in a dry run too
- `set-password` — set a user's password; development realms only (`ENV=dev`)
- `set-user-organization` — assign a user to organizations and org-level groups
- `status` — show current scopes, clients, and assignments

Authentication to Keycloak uses either admin user credentials (`--admin-user`) or a service account client (`celine-admin-cli`) whose secret is stored in `.client.secrets.yaml` after bootstrap. Both `bootstrap` and `sync` write that file through one merging writer, so a sync cannot delete the credential a bootstrap put there; it holds one realm at a time.

### 4. Rego Policies

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
clients.yaml ─────────┐   celine's own services — a whole realm on its own
clients.ds-host.yaml ─┤   the grants celine adds to ds's clients   ┐ only where a
<ds>/clients.yaml ────┘   ds's own declaration of those clients    ┘ dataspace runs
          │
          └─ merge (--overlay, repeatable)
                 │
                 ├─ compute diff
                 │    scopes to create/update
                 │    clients to create/update
                 │    scope assignments
                 │    audience mappers
                 │
                 ├─ apply changes ──> Keycloak Admin API
                 │
                 └─ .client.secrets.yaml
```

The `sync` command:

1. Loads `clients.yaml` (scopes + clients with `default_scopes` and `scopes_prefix`), merged with every `--overlay` file into one declaration — a realm may be declared by more than one party, and syncing half of it silently narrows the clients it mentions
2. Fetches current state from Keycloak (existing scopes, clients, assignments)
3. Computes a diff (plan): scopes to create/update, clients to create/update, scope assignments to add/remove
4. Applies changes idempotently
5. Merges the client secrets it generated into `.client.secrets.yaml`, keeping the entries this run did not touch — `celine-admin-cli` among them, which is what the next run with no `--admin-user` authenticates with

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
