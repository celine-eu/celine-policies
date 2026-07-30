# Scopes & Permissions

This document describes the OAuth scopes and service client configurations defined in `clients.yaml` and how they are enforced.

## Scope Naming Convention

```
{service}.{resource}.{action}
```

Special: `{service}.admin` grants full access to that service. The service prefix always matches the suffix of the `svc-{service}` client ID.

Examples:
- `digital-twin.values.read` — read digital twin values
- `pipelines.runs.write` — update pipeline runs
- `dataset.query` — execute dataset queries
- `mqtt.admin` — MQTT superuser access

## Platform Scopes

### Digital Twin

| Scope | Description |
|-------|-------------|
| `digital-twin.admin` | Full access to Digital Twin service |
| `digital-twin.values.read` | Read digital twin values |
| `digital-twin.values.write` | Write digital twin values |
| `digital-twin.simulation.read` | Read simulation data |
| `digital-twin.simulation.write` | Write simulation data |
| `digital-twin.simulation.run` | Execute simulations |
| `digital-twin.app.run` | Execute digital twin apps |

### Pipelines

| Scope | Description |
|-------|-------------|
| `pipelines.admin` | Full access to Pipeline service |
| `pipelines.runs.read` | Read pipeline runs |
| `pipelines.runs.write` | Update pipeline runs |
| `pipelines.job.read` | Read job details |
| `pipelines.job.write` | Modify job configuration |

### Dataset

| Scope | Description |
|-------|-------------|
| `dataset.admin` | Full access to Dataset service (includes restricted datasets) |
| `dataset.query` | Execute dataset queries |
| `dataset.read` | Read dataset metadata and schema |
| `dataset.write` | Write dataset data |

### REC Registry

| Scope | Description |
|-------|-------------|
| `rec-registry.admin` | Full administrative access |
| `rec-registry.import` | Import into the registry |
| `rec-registry.export` | Export from the registry |
| `rec-registry.lookup` | Lookup data |

### REC Onboarding

The onboarding console is the one service where **groups, not scopes, are the primary
authorization signal for humans**: a REC operator is authorised by membership of the
community's Keycloak organization plus one of the `admins`/`managers`/`editors`/`viewers`
org groups (see [Group Hierarchy](#group-hierarchy)), and carries no `onboarding.*`
scope at all. These scopes exist for the other subject type — service accounts and the
`onboarding-cli`, which have no organization and must therefore state intent explicitly.

| Scope | Description |
|-------|-------------|
| `onboarding.admin` | Full administrative access to the console API |
| `onboarding.recs.read` | List the communities the caller may administer |
| `onboarding.submissions.read` | Read submissions, with fiscal code and POD masked |
| `onboarding.submissions.reveal` | Unmask fiscal code and POD (each reveal is audit-logged) |
| `onboarding.submissions.write` | Edit submission fields and operator notes |
| `onboarding.submissions.review` | Take in charge, approve, reject, reopen |
| `onboarding.submissions.purge` | GDPR erasure of a submission and its files |
| `onboarding.enablement.retry` | Re-run a failed enablement step |
| `onboarding.enablement.revoke` | Reverse enablement — revoke credential, membership, login |
| `onboarding.audit.read` | Read a community's onboarding audit trail |
| `onboarding.export` | Export submissions or consented supply points |

`onboarding.submissions.purge` and `onboarding.enablement.revoke` are deliberately
**not** covered by `onboarding.submissions.review`, mirroring
`rec-registry.members.purge`: rejecting somebody is recoverable, erasing them or
revoking their credential is not, and a deployment must be able to grant one without
the other.

### Nudging

| Scope | Description |
|-------|-------------|
| `nudging.admin` | Admin nudging |
| `nudging.ingest` | Send notifications |

### Flexibility API

| Scope | Description |
|-------|-------------|
| `flexibility.admin` | Full access to the Flexibility API |
| `flexibility.commitments.read` | Read flexibility commitments |
| `flexibility.commitments.write` | Write and settle flexibility commitments |
| `flexibility.commitments.export` | Export flexibility commitments |
| `flexibility.committed.write` | Publish flexibility commitment events to MQTT |
| `flexibility.committed.read` | Subscribe to flexibility commitment events from MQTT |

### Grid API

| Scope | Description |
|-------|-------------|
| `grid.read` | Read DT grid resilience data (maps, trends, distributions) |
| `grid.alerts.read` | Read own alert rules and notification settings |
| `grid.alerts.write` | Create, update, and delete own alert rules |
| `grid.admin` | Full access to the Grid API (cross-user) |

### MQTT

| Scope | Description |
|-------|-------------|
| `mqtt.admin` | MQTT superuser access |

---

## Service Clients

Each CELINE service has its own OAuth client with `scopes_prefix` declaring which scope family it owns. The CLI uses this to validate scope ownership and automatically add audience mappers.

### svc-digital-twin

```yaml
scopes_prefix: digital-twin
default_scopes:
  - digital-twin.admin        # own resources
  - dataset.query              # reads datasets
  - pipelines.runs.read        # subscribes to pipeline updates
  - nudging.ingest             # send notifications
  - rec-registry.lookup        # lookup registry assets
  - flexibility.committed.read # subscribe to commitment events
  - flexibility.committed.write # publish commitment events (legacy)
```

### svc-pipelines

```yaml
scopes_prefix: pipelines
default_scopes:
  - pipelines.runs.read
  - pipelines.runs.write
  - rec-registry.export
  - flexibility.commitments.export
```

### svc-dataset-api

```yaml
scopes_prefix: dataset
default_scopes:
  - dataset.admin
```

### svc-nudging

```yaml
scopes_prefix: nudging
default_scopes:
  - nudging.admin
```

### svc-rec-registry

```yaml
scopes_prefix: rec-registry
default_scopes:
  - rec-registry.admin
```

### svc-flexibility

```yaml
scopes_prefix: flexibility
default_scopes:
  - flexibility.admin
  - digital-twin.values.read
  - dataset.query
  - nudging.ingest
  - rec-registry.lookup
  - flexibility.committed.write
  - pipelines.runs.read
```

### svc-grid

```yaml
scopes_prefix: grid
default_scopes:
  - grid.admin
  - digital-twin.values.read
  - dataset.query
  - nudging.ingest
  - pipelines.runs.read
```

### svc-onboarding

REC onboarding console API. Declared as a service client so `onboarding.*` has an owner
**and** so oauth2-proxy mints `aud: svc-onboarding` on user JWTs — without that, a REC
operator's browser token is rejected on audience validation before any policy runs.

```yaml
scopes_prefix: onboarding
default_scopes:
  - onboarding.admin
```

Not the same client as `svc-ds-onboarding`, which is the onboarding service's *outbound*
identity for the dataspace. One service, two clients: this one validates inbound
audiences, that one authenticates outbound M2M.

### svc-onboarding-cli

Service account for the `onboarding-cli` review and enablement commands. No
`scopes_prefix` — it owns nothing, it only calls:

```yaml
extra_audiences:
  - svc-onboarding
default_scopes:
  - onboarding.admin
```

### celine-cli

Admin CLI client — no `scopes_prefix` (sudo client, exempt from audience mapper generation):

```yaml
extra_audiences:
  - svc-digital-twin
  - svc-dataset-api
  - svc-rec-registry
  - svc-nudging
  - svc-flexibility
  - svc-grid
  - svc-onboarding
  - oauth2_proxy
default_scopes:
  - digital-twin.admin
  - pipelines.admin
  - dataset.admin
  - mqtt.admin
  - rec-registry.admin
  - nudging.admin
  - onboarding.admin
```

---

## User Groups

User authorization is group-based. Groups determine what resources a user can access (e.g., internal datasets, community data).

### Group Sources

Groups can come from two places in the JWT:

| Source | Claim | Assigned via |
|---|---|---|
| **Realm-level** | `groups: ["/admins"]` | Keycloak admin UI or `--group /admins` flag |
| **Org-level** | `organization.<alias>.groups: ["/viewers"]` | `sync-users` (automatic for REC participants) |

Realm-level groups are reserved for **platform management** (admins, managers). Regular REC participants receive org-level groups only.

### Group Hierarchy

Groups follow the standard role hierarchy (defined in `ROLE_HIERARCHY`):

| Group | Capabilities |
|---|---|
| `admins` | Full access to all resources |
| `managers` | Read/query access to internal datasets |
| `editors` | Used by the onboarding console (see below); unused elsewhere |
| `viewers` | Read/query access to internal datasets |

The same four names exist at realm level and inside every organization, and the
distinction carries meaning: an **org**-level group grants the capability for that
community only, a **realm**-level group grants it across every community. The onboarding
console is the first service to use the full hierarchy, mapping it to concrete
capabilities:

| Group | Onboarding console |
|---|---|
| `viewers` | read submissions (PII masked), read the audit trail |
| `editors` | + take in charge, edit fields and notes, unmask PII |
| `managers` | + approve, reject, reopen, retry a failed enablement step, export |
| `admins` | + GDPR erasure, reverse enablement |

### How Services Read Groups

All CELINE services use `extract_groups()` from `celine-sdk` to read groups from JWT claims. This function merges realm-level and org-level groups into a flat list:

```python
from celine.sdk.auth.jwt import extract_groups

groups = extract_groups(user.claims)
# ["viewers"] — regardless of whether it came from realm or org
```

Services must NOT use `claims.get("groups")` directly — it misses org-level groups.

### Multi-REC Isolation

Group-based access is a table-level gate ("can this user query internal datasets?"). Row-level isolation for multi-REC deployments is handled separately by `row_filters` in `governance.yaml`, which restrict visible rows based on the user's registered devices or community membership.

---

## Audience Mappers

The `oauth2_proxy_client` field in `clients.yaml` identifies the oauth2-proxy Keycloak client. The sync tool adds audience mappers for every service client that has a `scopes_prefix`, so that user JWTs issued through oauth2-proxy carry all service audiences and pass audience validation on each service.

Clients without `scopes_prefix` (like `celine-cli`) can declare `extra_audiences` explicitly.

---

## MQTT Authorization Model

For MQTT specifically, topic access is controlled by Rego policies (see [MQTT Integration](mqtt-integration.md)). The policies check:

1. **Service clients** — scope-based: requires the matching `{service}.{resource}.{verb}` scope, or a `{service}.admin` scope, or a resource wildcard scope.

2. **Users** — group-based: requires the matching group (`{service}.{resource}.{verb}`, `mqtt:{service}:{resource}:{verb}`, wildcard, or admin groups).

---

## clients.yaml Format

```yaml
realm: celine
oauth2_proxy_client: oauth2_proxy

scopes:
  - name: service.resource.action
    description: Human-readable description

clients:
  - client_id: svc-service-name
    name: Display Name
    secret: ${ENV_VAR:-default}
    scopes_prefix: service-name
    default_scopes:
      - service-name.admin
      - other-service.scope
```

Client secrets support environment variable substitution with `${VAR:-default}` syntax.
