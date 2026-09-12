# ADR-0007 — Realm-wide administration is declarable, for a holder with no public route

**Date:** 2026-09-12
**Status:** accepted

Supersedes the refusal in
[ADR-0003](ADR-0003-declare-realm-administration-as-a-group-scoped-permission.md) and
nothing else in it. `admin_permissions` stays, means what it meant, and remains the right
shape for a service that faces the public.

## Context

ADR-0003 gave `svc-onboarding` the narrowest grant Keycloak can express — `manage-members`,
`manage-membership`, `view-members` and `view` on `/participants` — and refused a
`realm_management_roles` field outright, on the grounds that a field granting realm-wide
`manage-users` sitting beside the narrow one would put that reach one YAML line away.

The refusal was right about the reach. It was made about a holder, and the holder has
changed.

**What the narrow grant costs, measured.** Everything built to make it survivable is
machinery that exists for no other reason:

- the `/participants` group itself, and `sync-users` filling it so the grant can see what
  it administers — [ADR-0005](ADR-0005-sync-users-files-participants-in-the-administered-group.md);
- `../onboarding`'s create-first-then-scan-on-`409`, which exists **only** because the
  grant forbids `GET /users?username=` and `GET /groups/{id}/members` ignores `search`;
- a per-organization permission per REC, which `clients.yaml` cannot express because it
  does not know organizations — deferred in ADR-0005, tracked as
  [celine-policies#6](https://github.com/celine-eu/celine-policies/issues/6);
- two traps that bite whoever adds the second grant: two clients granted on one group deny
  each other, and a grant does not descend to subgroups —
  [ADR-0004](ADR-0004-a-group-grant-carries-view-and-belongs-to-one-client.md).

And it still cannot do the job. Organization membership is the Organizations API, which
stays `403` on 26.6.0 even with realm-wide `Users: view + manage` granted the fine-grained
way; the fine-grained resource types are exactly `Clients`, `Groups`, `Roles` and `Users`,
with no Organizations among them. So participant provisioning was split between two
repositories that each held part of the right to do it — `sync-users` setting organization
membership, `../onboarding` setting the group — and on 2026-09-11, **10 of 45**
`/participants` members on demo3 had no `organization` claim as a result.

**A service with no public route inverts the trade.** The grant was narrow because the
holder was exposed. A holder that is not exposed can hold a coarse grant, and every item
above is then deleted rather than maintained.

## Decision

**`ClientConfig` gains `realm_management_roles`, a list of realm-management client roles
assigned to that client's service account.**

```yaml
  - client_id: svc-provisioning
    realm_management_roles:
      - manage-users
      - manage-realm
```

**One holder: `svc-provisioning`**, the participant provisioning service, which has no
public route and is the only thing that writes a participant account. `manage-users`
carries the realm-wide user search, edit and password reset the narrow grant had to work
around; `manage-realm` carries the Organizations API. Not the `realm-admin` composite,
which also grants client and identity-provider administration this service never performs —
`sync` does that, as a CLI, with an operator's credential.

**The grant is additive, and `sync` never revokes.** Nothing in this tool can tell a role it
granted from one an operator granted by hand — the classic role model has no sentinel, the
way `celine-policies:` marks a managed admin permission and `AUDIENCE_MAPPER_PREFIX` marks a
managed mapper. So a role held but not declared is left alone, dropping the field takes
nothing away, and there is no revoke action to produce. Withdrawing realm administration is
a deliberate act, done where it can be seen.

**A role the realm-management client does not offer stops the sync before it writes
anything**, which is the treatment [ADR-0002](ADR-0002-undefined-scope-grants-are-fatal.md)
gives a grant naming an undeclared scope, for the same reason: the alternative is a realm
that syncs clean and answers `403` to the one call the client exists to make.

**`sync` names every client that declares it**, on every run, in yellow. The field's danger
is that it is one line, so the review surface is the list of holders and not the count.

**It is not a grant key.** A second file may widen what a client may *ask for*; what it may
do to the realm is not something a file that does not own the client may hand out. Same
side of the line as `admin_permissions` — see `GRANT_KEYS`.

## Consequences

**The security argument is now a deployment property, and this repository cannot enforce
it.** "A coarse grant is safe because nothing outside can reach it" is true of an ingress
configuration, not of any code here. **A route added to `svc-provisioning` by accident
converts `manage-realm` into an internet-facing credential.** The guard belongs with the
ingress configuration in `../celine-dev`, where somebody adding a route will read it, and
`clients.yaml` says so at the declaration.

**Authorisation is still by scope.** `provisioning.participants.write` and
`provisioning.reconcile`, like every other service. Ingress restriction is defence in
depth, not the control: a caller inside the network still presents a token and still has to
hold the scope.

**What ADR-0003 forbade is now one YAML line away, and the answer is review rather than
absence.** A second client declaring this field is a change somebody has to argue for: the
test suite pins that `clients.yaml` has exactly one holder and that it does not hold
`realm-admin`, so widening the reach fails a test rather than passing unnoticed.

**`svc-onboarding` keeps its group-scoped grant until it stops needing it.** The order is
not negotiable: the service runs and its grant is verified, *then* `../onboarding` switches
to the API, and only then does the `admin_permissions` block leave `clients.yaml` and
`sync-users` stop filling `/participants`. Reversing the last two leaves a deployed
onboarding with no way to provision anybody. ADR-0003's decision stands until that lands,
and the group it created is left in the realm afterwards — it authorises nothing, so
removing it is cleanup without a deadline.

**It removes the dependency on 26.7.** `manage-realm` carries the Organizations API on
26.6.0, so organization membership stops being blocked on the upgrade. The upgrade remains
wanted for its own reasons.
