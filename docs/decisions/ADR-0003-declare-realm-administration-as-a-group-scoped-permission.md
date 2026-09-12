# ADR-0003 — A service account's realm administration is declared, and scoped to one group

**Date:** 2026-09-10
**Status:** accepted — the refusal of a `realm_management_roles` field is superseded by
[ADR-0007](ADR-0007-realm-wide-administration-is-declared-for-a-holder-with-no-public-route.md).
Everything else here stands.

## Context

`clients.yaml` could declare a client's scopes, audiences and whether it has a service
account. It could not declare **what that service account may do in the realm**. There was
no field for it, and `assign_realm_management_roles` was hard-wired to the roles
`celine-admin-cli` needs.

That gap acquired a consumer. `../onboarding` provisions a participant's login as
`svc-onboarding` (see ADR-0002 in that repository), and its service account needs the
ability to create a user, set their profile and password, find out whether they already
exist, and disable them on revocation. Those rights were granted **by hand**, so a realm
rebuilt from `clients.yaml` came back without them: the client list looked correct while
the realm was not, and the symptom appeared a long way away — every Admin API call refused
with `403`, surfacing to a REC operator as
`Login identity could not be provisioned: Keycloak user lookup failed (403)`.

This is the drift class [ADR-0001](ADR-0001-merge-in-the-loader.md) was written about: the
declaration and the realm disagree, and nothing says so.

The obvious repair is a `realm_management_roles: [manage-users, view-users]` field. It was
not taken, for two reasons measured against the Keycloak this repository pins
(`keycloak/version.txt` → 26.6.0).

**`manage-users` is realm-wide.** It is update, delete, password reset and disable on
*every* account in the realm — operator accounts and other services' users included — held
by the service that faces the public onboarding wizard, in order to create participants.

**Fine-grained admin permissions are no longer a preview.** The reason to keep realm-wide
roles as a documented floor was that the alternative might not be available. On 26.6 the
server reports `ADMIN_FINE_GRAINED_AUTHZ_V2` as `type=DEFAULT, enabled=true`, with the
older `ADMIN_FINE_GRAINED_AUTHZ` deprecated and off. It is available by default.

## Decision

**`ClientConfig` gains `admin_permissions`, and it can express only a group-scoped grant.**

```yaml
  - client_id: svc-onboarding
    admin_permissions:
      groups:
        - path: /participants
          scopes: [manage-members, manage-membership, view-members]
```

`sync` enables `adminPermissionsEnabled` on the realm, ensures the group, creates one
client policy per client and one scope permission per declared group, and converges both
directions — a narrowed scope list rewrites the permission and a group dropped from the
declaration has it deleted, neither requiring `--prune`.

**There is deliberately no `realm_management_roles` field.** A field granting realm-wide
`manage-users` sitting beside this one would put the reach this decision exists to avoid
one YAML line away. A deployment on a Keycloak without the feature keeps granting by hand,
which is what everyone did before this change.

**The group is an ordinary realm group, not an organization's group.** Scoping to a REC's
own org group was the preferred shape and does not work. Measured on 26.6.0: the
fine-grained resource types are exactly `Clients`, `Groups`, `Roles` and `Users` — there is
no Organizations type; a `Groups` permission naming an **org** group's id is accepted with
a 201 and grants nothing; the ordinary group API refuses org groups outright
(`Cannot manage organization related group via non Organization API`); and the
Organizations API stays `403` even with realm-wide `Users: view + manage` granted this way.

## Consequences

**What the grant contains, and what it does not.** Measured with only
`Groups: manage-members, manage-membership, view-members` on `/participants` and no
realm-management role at all: creating a user into the group, and reading, updating,
disabling and password-resetting a member all succeed; the same operations on an operator's
account are refused with `403`, as are creating a user in no group, creating one in a group
that was not granted, listing the realm's users, and listing its clients.

**`manage-members` and `manage-membership` must be declared together.** They authorise
different halves of `POST /users` with a `groups` entry — making the user, and putting them
in the group. Granted either alone, Keycloak creates the permission with a 201 and refuses
every creation with a 403. `sync` warns when it sees one without the other, and does not
refuse it, because administering members that already exist is a legitimate narrower grant.

**Enabling the feature disturbs nothing that already works.** With
`adminPermissionsEnabled` set, a service account holding `realm-management` roles the
classic way is unaffected — `celine-admin-cli` included. The two models coexist. The flag
is also reversible: setting it back to `false` leaves the `admin-permissions` client and
its permissions intact, and re-enabling returns the same client uuid.

**`--prune` must never reach the `admin-permissions` client.** Keycloak creates it when the
feature is enabled and `clients.yaml` does not declare it, so it lands in `orphan_clients`
unless exempted — and pruning it would delete every permission with it. It is exempted
alongside `realm-management` and the other clients Keycloak owns.

**Only names carrying the `celine-policies:` sentinel are read or written**, the same
discipline `AUDIENCE_MAPPER_PREFIX` enforces for mappers. A permission an operator creates
in the admin console is invisible to the plan and survives a sync untouched.

**A group this tool created is never deleted.** Revoking a permission leaves the group and
its members in place, because deleting a group deletes nobody's membership quietly — it
deletes the group. Removing a group is a deliberate act, not a consequence of editing a
grant.

**It does not take effect until `../onboarding` changes.** `sync` can grant the permission;
it cannot make the consumer use it, and today the consumer cannot. `_user_payload` sends no
`groups` key, so `POST /users` is refused under group scoping, and `_find_user` uses the
realm-wide `/users` search, which is also refused — the duplicate check has to move to
`GET /groups/{id}/members?search=`. Until both land, `svc-onboarding` keeps its hand-granted
realm-management roles and provisioning keeps working, which is precisely why granting the
narrower permission first is safe. The alternative considered and rejected was to also
grant realm-wide `Users: view` so the existing lookup keeps working; it is read-only, but
it would let the service read every account in the realm, and the whole point here is that
it should not.
