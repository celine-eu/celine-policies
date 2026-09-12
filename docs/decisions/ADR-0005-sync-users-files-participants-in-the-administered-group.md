# ADR-0005 — `sync-users` files participants in the group the declaration administers

**Date:** 2026-09-10
**Status:** superseded by
[ADR-0007](ADR-0007-realm-wide-administration-is-declared-for-a-holder-with-no-public-route.md).

`sync-users` still reads `admin_permissions` and still files participants into every group
it names — the behaviour is untouched. Nothing declares one any more, so it files them
into none, and `/participants` stops being refilled. The group is left in the realm with
its existing members; it authorises nothing, and removing it is an operator's deliberate
act with no deadline.

## Context

[ADR-0003](ADR-0003-declare-realm-administration-as-a-group-scoped-permission.md) scopes a
service account's realm administration to the members of one group. A participant outside
that group is invisible to the service: it can neither find the account nor act on it.

`sync_users` creates users with the REC organization's membership, the org `viewers` group,
and whatever `--group` paths were passed. None of that is the administered group, so every
participant this repository provisions from a REC registry lands outside the grant.
`../onboarding` then attempts to create the same person, Keycloak answers
`409 User exists with same username`, the scan of the group does not find them, and the
enablement step fails naming an account that plainly exists. That failure is the agreed
behaviour on the consumer's side — it tells a human the account exists and is not in the
group — but nothing on this side could put it there.

The group is not the only per-participant container in play. This repository already
maintains a Keycloak **organization** per REC, and files each participant in it. That is
the natural per-community grouping, and it is unusable for this purpose: the Organizations
API is outside fine-grained admin permissions entirely, and answers `403` even to a service
account holding realm-wide `Users: view + manage` granted that way.

## Decision

**`sync-users` reads the `admin_permissions` block and adds every participant it processes
to the groups it declares.** The paths come from the same declaration `sync` grants from,
so the command that fills a group and the command that grants over it cannot name different
groups. `--no-admin-groups` opts out.

**It applies to accounts that already exist, not only to new ones**, which makes a re-run
the backfill for participants provisioned before the group was declared. No separate
backfill command is owed.

**The group must already exist.** `sync` owns realm structure and creates the group when it
grants the permission; a missing group means the realm has not been synced from the
declaration `sync-users` just read, and creating it here would paper over that. It is
resolved before any user is touched, the way `--group` already is, so a run does not stop
half way leaving some participants filed and some not.

## Consequences

**The administered group is flat, and it will hold every participant on the deployment.**
This is the cost, it is known, and it was chosen deliberately over the alternative below.
Its sharp edge is the consumer's lookup: `GET /groups/{id}/members` ignores `search`
(ADR-0004), so finding one participant is a paged scan of the whole group.

**Per-organization groups were measured before deciding, and cost one Keycloak permission
per organization.** A grant on `/participants` does **not** descend to
`/participants/<org>` for anything group-addressed — measured on 26.6.0 holding all seven
`Groups` scopes, and even on a child group the service account had just created itself:
`POST /users` into the child, `group-by-path` on it, `GET /groups/{id}` and
`GET /groups/{id}/members` are all `403`. A permission on the child alone works completely.
Subgroup members are also not members of the parent — the parent's member list excludes
them, and `?subGroups=true` changes nothing.

So the per-org shape is a different change rather than a larger version of this one:
`clients.yaml` does not know organizations and the REC registry does, so granting would move
from `clients.yaml`-driven `sync` to registry-driven `sync-users`, and the consumer would
have to resolve an organization's group rather than one fixed path. It needs its own ADR,
and the measurements are recorded in
[celine-policies#6](https://github.com/celine-eu/celine-policies/issues/6).

One thing does descend, and is worth not re-deriving: **member-addressed calls**. Reading,
updating and password-resetting a user who is only in `/participants/<org>` all succeed
under a grant on `/participants`, while the same calls on a member of an unrelated group
are `403`. A parent grant can administer everyone beneath it; it cannot create into a child
or find anyone there.

**A deployment that declares no `admin_permissions` sees `sync-users` behave exactly as
before** — no group is resolved and no membership is added.
