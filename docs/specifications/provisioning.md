# Provisioning

The service that writes participant accounts into the realm: who may call it, and what it
creates for a community. The routes are described in the
[API reference](../api-reference.md#provisioning-service).

---

### REQ-0001 — only `svc-onboarding` holds a `provisioning.*` scope

Apart from `svc-provisioning` itself, which holds `provisioning.admin` over its own family,
**no client but `svc-onboarding` holds any `provisioning.*` scope**, as a default or an
optional scope, and no client but `svc-onboarding` receives a token addressed to
`svc-provisioning`. It holds over `clients.yaml` alone and over `clients.yaml` merged with the
ds-host overlay, because an overlay may add grants.

Onboarding is the single point of access to the provisioning service
([ADR-0010](../decisions/ADR-0010-on-a-deployed-realm-members-arrive-through-onboarding.md)).
A component that wants an account changed goes through onboarding instead of holding a grant
of its own, so a second holder is a change somebody has to argue for, and fails a test first.

### REQ-0002 — a reconcile sets up a community that has no members yet

**Status:** planned

`POST /reconcile/{community}` ensures the community's Keycloak organization, its org roles and
its org groups (the whole of `ROLE_HIERARCHY`: `admins`, `managers`, `editors`, `viewers`)
**even when the registry community has no active member**, and answers `200` with
`members: 0`. A second call creates nothing.

A community the registry does not have is `404 community_not_found`, and nothing is created
in Keycloak.

This is how a clean community gets its organization on a deployed realm, before any member
is approved and before a platform admin adds the managers' group
([ADR-0010](../decisions/ADR-0010-on-a-deployed-realm-members-arrive-through-onboarding.md)).
The `404` already holds; the zero-member setup is what the code does today and no test pins.

### REQ-0003 — filing a participant keeps the org groups they already have

`PUT /participants/{community}/{key}` on an account that already exists and is in the
organization's `managers` (or `admins`) group adds the `viewers` membership and **leaves the
existing org group memberships in place**. It removes no org group and no realm group.

A manager who is also a participant onboards with the address their manager account carries,
and approval files that same account
([ADR-0010](../decisions/ADR-0010-on-a-deployed-realm-members-arrive-through-onboarding.md)).
Losing `managers` there would lock the manager out of their own dashboard.
