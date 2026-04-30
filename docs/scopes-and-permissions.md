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
  - oauth2_proxy
default_scopes:
  - digital-twin.admin
  - pipelines.admin
  - dataset.admin
  - mqtt.admin
  - rec-registry.admin
  - nudging.admin
```

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
