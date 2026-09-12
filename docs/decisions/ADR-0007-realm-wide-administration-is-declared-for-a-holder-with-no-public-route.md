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
stays `403` even with realm-wide `Users: view + manage` granted the fine-grained way; the
fine-grained resource types are exactly `Clients`, `Groups`, `Roles` and `Users`, with no
Organizations among them. Measured on 26.6.0 when ADR-0003 was written and unchanged on
the 26.7.3 `keycloak/version.txt` now pins. So participant provisioning was split between two
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

**And "no route" was the wrong shape of that guard — amended 2026-09-12, the same day.**
`docker-compose.yaml` published no port and `../celine-dev`'s Caddyfile carried a
DO-NOT-ADD-A-ROUTE block, on the reasoning that callers reach this service by container
name on `celine_security_net`. **No caller can.** Nothing joins that network from another
compose project, so `http://provisioning:8010` resolved from nowhere: `../onboarding` runs
in a project and a network of its own, and on a developer's machine as often from source on
the host with no Docker network at all. Measured on the demo3 deployment — neither half of
onboarding could resolve the name, so the login step this ADR exists to enable could not be
exercised anywhere.

So the port is published and there is one route, `provisioning.internal.celine.localhost`,
a **host of its own** rather than a path under the public `api.celine.localhost`. The
property this ADR rests on is unchanged and is still not enforceable from this repository —
**nothing outside the deployment may reach this service** — but it is now one hostname and
one published port to keep off a public zone rather than an absence to preserve. On a dev
machine the boundary is the machine. **In a real deployment it is unestablished**, and it is
the thing to settle before this ships: see the store's
`knowledge/the-provisioning-service-is-safe-only-because-it-is-unreachable.md`.

**Authorisation is still by scope.** `provisioning.participants.write` and
`provisioning.reconcile`, like every other service. Ingress restriction is defence in
depth, not the control: a caller inside the network still presents a token and still has to
hold the scope.

**What ADR-0003 forbade is now one YAML line away, and the answer is review rather than
absence.** A second client declaring this field is a change somebody has to argue for: the
test suite pins that `clients.yaml` has exactly one holder and that it does not hold
`realm-admin`, so widening the reach fails a test rather than passing unnoticed.

**`svc-onboarding`'s group-scoped grant is withdrawn, and with it everything that existed
to make it survivable.** ADR-0003 through ADR-0005 are superseded in substance, not only in
their refusal of this field: no client declares `admin_permissions`, `sync-users` files
participants into no realm group, and `../onboarding` holds no Keycloak right at all — it
calls this service with `provisioning.participants.write`. The mechanism stays in the code
and in the tests, because a group-scoped grant is still the right shape if one is ever
needed again; nothing needs one now.

**Withdrawing it is not free, and the cost is a deploy window.** `sync` converges admin
permissions without `--prune`, so the next sync revokes the permission — and an onboarding
still calling the Admin API then fails every approval with a `403`, surfacing to a REC
operator as "Login identity could not be provisioned". The realm change and
`../onboarding`'s cutover therefore have to land together. That was a deliberate decision
taken with that cost understood, rather than the staged order this ADR was first drafted
with.

**The `/participants` group is left in the realm.** `sync` never deletes a group it made —
deleting one deletes everybody's membership of it quietly — so the group survives with its
members and authorises nothing at all: it appears in no capability table and no client is
granted over it. Removing it is an operator's deliberate act, and there is no deadline on
it.

**The grant was verified before this was accepted, and the negative control is half of
it.** On a throwaway realm with `manage-users` + `manage-realm` and nothing else, every
call the provisioning package makes succeeds: the realm write that enables organizations,
the organization with its org roles and org groups, creating a user and placing it in both,
the two realm-wide searches ADR-0003's grant forbids, password reset, disable and
re-enable, and both ensures re-run idempotently. **`list_clients` is refused**, which is
what makes this measurably not `realm-admin`. Run on 26.6.0 and on 26.7.3 with identical
results; the details are in the store's work directory for this plan.

**It removed the dependency on the 26.7 upgrade, which has since landed anyway.**
`manage-realm` carried the Organizations API on 26.6.0 too, so this decision never needed
the upgrade to be true — it was taken while 26.6.0 was still the pinned version. That is
now history rather than a live consideration: the platform runs 26.7.3 and 26.6.x is gone.
