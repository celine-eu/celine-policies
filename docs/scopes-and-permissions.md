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
| `onboarding.members.invite` | Email a registry member an invitation or a password reset, on behalf of the manager whose token is forwarded |

**`onboarding.members.invite` is delegated, and useless alone.** Onboarding allows it only to a
service that also forwards a manager's verified access token (`X-Acting-User-Token`), and only
when that manager holds `admins` or `managers` on the REC. No service sends on its own, not even
one holding `onboarding.admin`. The scope is held by `svc-community` alone, as an optional scope;
see [svc-community](#svc-community).

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

### REC Manager Dashboard

| Scope | Description |
|-------|-------------|
| `community.read` | Read aggregate REC manager data |
| `community.devices.read` | Read technical device-level data without participant identity |
| `community.nudging.read` | Read aggregate nudging performance |
| `community.alerts.write` | Manage and acknowledge REC alerts |
| `community.objectives.write` | Manage REC objectives |

### MQTT

| Scope | Description |
|-------|-------------|
| `mqtt.admin` | MQTT superuser access |

### Provisioning

The service that writes participant accounts into the realm, and the only thing that does.

| Scope | Description |
|-------|-------------|
| `provisioning.admin` | Full access to the provisioning service |
| `provisioning.participants.write` | Create or update one participant's account, email them an invitation or a password reset, disable it |
| `provisioning.reconcile` | Sweep one community from the registry and reconcile the realm against it |

**Only `svc-onboarding` holds a `provisioning.*` scope**, apart from the service itself
(`provisioning.admin`, its own family). Onboarding is the single point of access to the
provisioning service (requester, 2026-09-14): no other client calls it directly, and a
`provisioning.*` grant to one is a change to argue for. `tests/test_provisioning_scope_holders.py`
fails when a second client is granted one, over `clients.yaml` and the ds-host overlay.

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

### svc-community

The BFF behind the REC manager dashboard. Declared with a prefix so `community.*` has an owner
and oauth2-proxy mints `aud: svc-community` on a manager's browser token.

```yaml
scopes_prefix: community
default_scopes:
  - community.read
  - community.devices.read
  - community.nudging.read
  - community.alerts.write
  - community.objectives.write
  - digital-twin.values.read
  - dataset.query
  - rec-registry.read          # aggregate population, and member names for the members page
  - nudging.analytics.read
optional_scopes:
  - onboarding.members.invite  # "Send invitation" / "Reset password", through onboarding
```

`rec-registry.read` also gives the members page its names. They are read per request and never
persisted, and no email, user id, DID or supply point leaves the BFF process.

`onboarding.members.invite` is **optional, not default**. The Digital Twin forwards this
client's default-scope token to dataset-api, and a send capability must not travel there. The
BFF requests the scope only for its call to onboarding, and forwards the manager's own token
beside it. The audience mapper onto `svc-onboarding` is derived from the scope, and a realm
has it only after `keycloak sync`.

It holds no `provisioning.*` scope: the provisioning service is reached through onboarding
only. See [Provisioning](#provisioning).

### svc-onboarding

REC onboarding console API. Declared as a service client so `onboarding.*` has an owner
**and** so oauth2-proxy mints `aud: svc-onboarding` on user JWTs — without that, a REC
operator's browser token is rejected on audience validation before any policy runs.

```yaml
scopes_prefix: onboarding
default_scopes:
  - onboarding.admin
  - provisioning.participants.write
```

**It administers nothing in the realm, and that is the point.** It held a fine-grained
grant over `/participants` for as long as it was the thing provisioning a participant's
login — the narrowest grant Keycloak can express, and still the wrong shape: a service
facing the internet with admin rights over accounts, which could not finish the job anyway
because organization membership is the Organizations API. `svc-provisioning` took it over,
and `provisioning.participants.write` above is how onboarding reaches it. The audience
mapper onto `svc-provisioning` is derived from that one line.

Do not add a grant back. If something here needs a realm object changed, it belongs behind
the provisioning service.

Not the same client as `svc-ds-onboarding`, which is the onboarding service's *outbound*
identity for the dataspace. One service, two clients: this one validates inbound
audiences, that one authenticates outbound M2M.

See [Realm administration](#realm-administration) below for what that block is and who
else holds one.

### svc-onboarding-cli

Service account for the `onboarding-cli` review and enablement commands. No
`scopes_prefix` — it owns nothing, it only calls:

```yaml
extra_audiences:
  - svc-onboarding
default_scopes:
  - onboarding.admin
```

### svc-provisioning

The participant provisioning service. It holds **realm-wide** administration — the only
client that does — and is the only thing that writes a participant account:

```yaml
scopes_prefix: provisioning
realm_management_roles:
  - manage-users
  - manage-realm
default_scopes:
  - provisioning.admin
  - rec-registry.export
```

`manage-users` carries the realm-wide user search, edit and password reset that the
group-scoped grant on `svc-onboarding` has to work around; `manage-realm` carries the
Organizations API, which no fine-grained permission expresses at all. Not the
`realm-admin` composite, which also grants client and identity-provider administration
this service never performs — `sync` does that, as a CLI, with an operator's credential.

`rec-registry.export` and nothing else on the registry side: this service reconciles
Keycloak *from* the registry and must never be able to write to it.

**What makes the coarse grant safe is that nothing outside the network can reach it, and
this repository cannot enforce that.** A route added to this service by accident converts
`manage-realm` into an internet-facing credential. The guard lives with the ingress
configuration, not here. See
[ADR-0007](decisions/ADR-0007-realm-wide-administration-is-declared-for-a-holder-with-no-public-route.md).

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
| **Realm-level** | `groups: ["/admins"]` | Keycloak admin UI, or `sync-users --group /admins` given explicitly |
| **Org-level** | `organization.<alias>.groups: ["/viewers"]` | `sync-users` and the provisioning service (automatic for REC participants) |

Realm-level groups are reserved for **platform management** (admins, managers). Regular REC participants receive org-level groups only: the provisioning service assigns no realm group, and `sync-users` assigns one only when `--group` names it. The `taskfile.yaml` dev tasks no longer pass `--group /viewers` (2026-09-14); an account already in realm `/viewers` keeps that membership until an operator removes it.

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

## Hardcoded Claims

`hardcoded_claims` pins a claim in this client's tokens to a fixed string, overriding
whatever Keycloak would otherwise emit. Each entry becomes one
`oidc-hardcoded-claim-mapper` named `claim-<claim>`, on the access token and on
introspection — never on the id token or userinfo, where a pinned `sub` would misreport
who is signed in.

```yaml
clients:
  - client_id: svc-ds-example-rec
    hardcoded_claims:
      sub: ${EXAMPLE_REC_DID:-did:web:example-rec.localhost}
```

**It exists for `sub`.** Eclipse EDC's management API takes the participant context
straight from the access token's `sub`, and Keycloak's `sub` for a service account is that
account's UUID — so without this the connector resolves a participant nobody declared.

`sync` converges on the declaration: a changed value is rewritten in place, and a claim
dropped from the file has its mapper removed. Only mappers named `claim-*` *and* of type
`oidc-hardcoded-claim-mapper` are ever read or written, so one added by hand in the admin
console is left alone.

Like `secret` and `scopes_prefix`, it is part of a client's **identity**: the one file
that declares the client declares this, and an overlay carrying it is refused.

---

## MQTT Authorization Model

For MQTT specifically, topic access is controlled by Rego policies (see [MQTT Integration](mqtt-integration.md)). The policies check:

1. **Service clients** — scope-based: requires the matching `{service}.{resource}.{verb}` scope, or a `{service}.admin` scope, or a resource wildcard scope.

2. **Users** — group-based: requires the matching group (`{service}.{resource}.{verb}`, `mqtt:{service}:{resource}:{verb}`, wildcard, or admin groups).

---

## Realm administration

Scopes say what a client may **ask for**. They say nothing about what its service account
may **do to the realm** — create a user, reset a password, disable an account. That is a
separate mechanism, and there are two ways to declare it.

| Field | Reach | Who holds it |
|---|---|---|
| `admin_permissions` | the members of one named group | a service that faces the public |
| `realm_management_roles` | realm-wide | a service with no public route |

The first is below. The second is one line, is deliberately hard to justify, and is
described under [Realm-wide administration](#realm-wide-administration).

### Who holds one

Two, and the list is meant to stay short — a third entry is a change somebody has to argue
for, and the test suite fails if one appears in `clients.yaml` without it.

| Holder | Reach | Why |
|---|---|---|
| `celine-admin-cli` | realm-wide, eight `realm-management` roles | the operator credential `keycloak bootstrap` creates. **Not declared in `clients.yaml`**: `sync` runs as it, so declaring it would let a sync rewrite its own credential — and it is exempt from `--prune` for the same reason |
| `svc-provisioning` | realm-wide, `manage-users` + `manage-realm` | the only writer of participant accounts, safe to hold that only because it has no public route |

**No client declares `admin_permissions`.** `svc-onboarding` held one over `/participants`
until `svc-provisioning` took the job over; the group-scoped mechanism below is documented
and tested because it is the right shape if a grant is ever needed again, not because
anything uses it.

`celine-cli` is **not** an administrator despite the name — it is a sudo *API* client
holding every service's `.admin` scope and no Keycloak right at all.

### Group-scoped administration

Declared with `admin_permissions`:

```yaml
  - client_id: svc-onboarding
    admin_permissions:
      groups:
        - path: /participants
          scopes: [manage-members, manage-membership, view-members, view]
```

The grant is scoped to the members of one group. A service account holding the block above
may create a user **into** `/participants` and read, update, disable and password-reset a
member of it — and may do none of those things to anybody else, including operator
accounts. Keycloak's realm-wide `manage-users` role would have reached every account in the
realm to do the same job.

### The scopes

Keycloak defines these on its `Groups` resource type. A name not on this list is refused
when the file is loaded, before anything is authenticated.

| Scope | Grants |
|---|---|
| `view-members` | read the group's members, and search within them |
| `manage-members` | create, update, disable and password-reset a member |
| `manage-membership` | add and remove members of the group |
| `view` / `manage` | read and modify the group itself |
| `manage-membership-of-members` | change members' membership of *other* groups |
| `impersonate-members` | impersonate a member |

**`manage-members` and `manage-membership` are a pair.** Creating a user in a group needs
both: one authorises making the user, the other authorises putting them in the group.
Granted either alone, Keycloak creates the permission without complaint and refuses every
creation with a `403`. `sync` warns when it sees one without the other.

**Any member scope needs `view` beside it.** The member scopes do not let a service account
name the group they are about: holding them and nothing else, `group-by-path`,
`GET /groups?search=` and even `GET /groups/{id}` on the administered group all answer
`403`. Every member call is addressed by that id, so such a grant can create a member and
can never find one again — and a service that resolves its group lazily keeps provisioning
and fails only later, on a lookup. `sync` warns when a member scope appears without `view`.
Adding `view` does not widen the grant beyond the group: `GET /groups`, which lists the
realm's groups, stays `403`.

**One client per group.** Two clients granted the same group deny *each other*: the
admin-permissions resource server decides `UNANIMOUS`, so a permission whose client policy
does not name you votes against you, and both clients end up with `403` on everything —
including the one that was working before the second declaration was added. Keycloak
creates both permissions with a `201` and reports nothing, so the declaration is refused
when the file is loaded instead.

### What sync does with it

On a realm that declares nothing, nothing — no request is made and no action is planned.
Where a client does declare it, `sync` checks that `keycloak bootstrap` has enabled
fine-grained admin permissions on the realm (`adminPermissionsEnabled` in `platform.yaml`,
which leaves existing `realm-management` role grants working exactly as before) and refuses
otherwise, ensures the group exists, and creates one policy and one permission per declared
group. See [ADR-0008](decisions/ADR-0008-each-cli-command-owns-one-level-of-the-realm.md).

It converges in both directions without `--prune`: narrowing the scope list rewrites the
permission, and removing a group from the declaration revokes it. Only permissions named
with the `celine-policies:` prefix are ever read or written, so anything created by hand in
the admin console survives a sync untouched. A group that `sync` created is never deleted —
revoking a permission leaves the group and its members alone.

## Realm-wide administration

One client holds it — `svc-provisioning` — and the field is one line:

```yaml
  - client_id: svc-provisioning
    realm_management_roles:
      - manage-users
      - manage-realm
```

These are `realm-management` client roles, assigned to the client's service account. They
are **realm-wide**: `manage-users` is update, delete, password reset and disable on every
account in the realm, and `manage-realm` includes the Organizations API. There is no
narrower way to reach organization membership — the fine-grained resource types are
`Clients`, `Groups`, `Roles` and `Users`, with no Organizations among them, and the
Organizations API answers `403` even with realm-wide `Users: view + manage` granted the
fine-grained way. Measured on 26.6.0 and re-run on the 26.7.3 this repository ships.

**What makes it acceptable is the holder, not the grant.** A service with no public route
can hold a coarse grant; the service that faces the public onboarding wizard could not,
which is what `admin_permissions` exists for. That argument is a property of the ingress
configuration and **cannot be enforced from this repository** — a route added to
`svc-provisioning` by accident converts `manage-realm` into an internet-facing credential.

**What `sync` does with it.** Nothing at all on a declaration that names no roles. Where a
client declares them, `sync` prints the holders in yellow on every run, ensures the
realm-management audience mapper (without it the role mappings never reach the token and
every Admin API call is a `403` with the roles plainly assigned), and assigns the roles the
service account is missing.

It is **additive and never revokes**: nothing here can tell a role this tool granted from
one an operator granted by hand, so a role held but not declared is left alone and dropping
the field takes nothing away. Withdrawing realm administration is a deliberate act, done
where it can be seen.

A role the realm-management client does not offer **stops the sync before it writes
anything**, naming every offender and listing what is available — the same treatment
[ADR-0002](decisions/ADR-0002-undefined-scope-grants-are-fatal.md) gives a grant naming an
undeclared scope, and for the same reason.

Read [ADR-0007](decisions/ADR-0007-realm-wide-administration-is-declared-for-a-holder-with-no-public-route.md)
before adding a second holder.

### What sync-users does with it

`sync-users` reads the same block and adds every participant it processes to the groups it
declares, so a grant over a group is a grant over the participants this tool creates. It
applies to accounts that already exist as well as new ones, which makes a re-run the
backfill for participants provisioned before the group was declared.

**Nothing declares one, so it files participants into no realm group.** `/participants` is
not refilled, and **the group has been deleted** — an operator's deliberate act on
2026-09-12, because it authorised nothing: it appeared in no capability table and no client
was granted over it. `sync` will not recreate it; it only ever made the group because a
client declared a grant over it, and none does.

`sync` never deletes a group itself, and that has not changed — deleting one deletes
everybody's membership of it quietly, which is not something a declaration-driven tool
should do as a side effect of an edit. Deleting the group removed 45 inert memberships on
the local dev realm and nothing else: the accounts, their realm `/viewers` membership (which
the dev tasks' `--group /viewers` gave them, and no longer do) and their REC organization
membership — the one that carries the `organization` claim — are
untouched.

The group must already exist — `sync` creates it when it grants the permission, and
`sync-users` fails before touching any user rather than creating realm structure of its
own. `--no-admin-groups` turns the behaviour off.

### Where sync-users gets its members, and the scope that costs

`sync-users` reads REC definitions either from a YAML file or, with `--from-registry`, from
the live rec-registry. The file is a picture of the community at export time, so a run
against one leaves out everybody `onboarding` has approved since; the registry reconciles
what is true. See
[ADR-0006](decisions/ADR-0006-the-registry-is-the-source-of-members.md).

Reading the registry needs a Keycloak client holding **`rec-registry.export`** and an
audience of `svc-rec-registry`. The default is `celine-cli`, which holds
`rec-registry.admin` — and that is wider in a direction worth stating plainly: through the
admin override it also satisfies `rec-registry.import`, which deletes a community with
every member in it, and `rec-registry.members.purge`.

Nothing in `clients.yaml` was changed for this, and no realm narrowing is in place. What
keeps it bounded is the code: `src/celine/policies/cli/keycloak/registry.py` names one
read-only registry method, and a test fails if a second is touched. To narrow it properly,
declare a client with `rec-registry.export` alone and point `--registry-client-id` at it —
no code change is needed.

`--check` reads the same sources and writes nothing, exiting non-zero when a member of the
source has no account, is outside their REC organization, or is outside a group declared
here. Organization membership is not a health probe, so this is the probe:

```console
$ celine-policies keycloak sync-users --from-registry \
    --registry-url http://api.celine.localhost/rec-registry --check
example-renewable-community:
  ✗ example-renewable-community/20260910-1a2b3c4d (a.person@example.org): not in the REC
    organization — no `organization` claim, so no org-scoped policy resolves them
```

### Requirements

Keycloak 26.2 or later with `ADMIN_FINE_GRAINED_AUTHZ_V2`, which is a default-enabled
feature on the 26.7 image this repository ships. An **organization's** group cannot be
targeted — only realm groups; see
[ADR-0003](decisions/ADR-0003-declare-realm-administration-as-a-group-scoped-permission.md)
for what was measured.

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
    # Optional — what this client's service account may administer.
    admin_permissions:
      groups:
        - path: /some-group
          scopes: [manage-members, manage-membership, view]
    # Optional — claims pinned into this client's tokens.
    hardcoded_claims:
      sub: ${PARTICIPANT_DID:-did:web:example.localhost}
```

Client secrets support environment variable substitution with `${VAR:-default}` syntax,
and so does every other string in the file — `hardcoded_claims` values included.
