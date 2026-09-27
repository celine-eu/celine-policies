# ADR-0010 — on a deployed realm, members arrive through onboarding, and a community's organization through the provisioning reconcile

**Date:** 2026-09-27
**Status:** accepted

Refines [ADR-0006](ADR-0006-the-registry-is-the-source-of-members.md) and
[ADR-0008](ADR-0008-each-cli-command-owns-one-level-of-the-realm.md). Neither is superseded:
the registry is still the source of members, a YAML file is still a seed, and each command
still owns one level of the realm. What changes is **where** the seed and `sync-users` may
write.

## Context

ADR-0006 kept the file path of `sync-users` working and said it was **not deprecated**:
"bootstrap runs before the registry holds anything, and an offline run is real". ADR-0008
named three writers of the organizations and users level: the provisioning service,
`sync-orgs` and `sync-users`.

A deployed community seeded that way carries accounts nobody signs in with: placeholder
names and addresses, one account per imported member, made from a file rather than from a
person. Repairing them in place, adopting them at approval or replacing them when a meter is
attached each puts migration logic in the product, and was rejected by the requester
(2026-09-27). The decision instead is that **a community starts clean**: a new registry
community and a new Keycloak organization, managers first, no members, and every person
entering through `../onboarding`.

Two things stood in the way:

- **Nothing that runs on a deployed realm creates an organization with no members.**
  `sync-users` exits when its source holds no active member, before it ensures anything
  (`src/celine/policies/cli/keycloak/commands/sync_users.py`). `POST /reconcile/{community}`
  does call `ensure_community` before it walks the members, so an empty community gets its
  organization, org roles and org groups — but nothing promised that, and **nobody holds
  `provisioning.reconcile`**.
- **Onboarding is the single point of access to the provisioning service** (requester,
  2026-09-14; `tests/test_provisioning_scope_holders.py`), so a second caller of `reconcile`
  would break the rule this repository tests.

## Decision

**On a deployed realm, `sync-users` writes nothing, from either source.** The YAML seed and
`sync-users` are local development: the compose stack, a developer's realm, the fixtures.
ADR-0006's reasons for keeping the file path — a registry that holds nothing yet, an offline
run — are reasons of local development, and stay true there. Its one-parser property stands
unchanged.

**The command enforces it: `sync-users` refuses unless `ENV=dev`** (requester, 2026-09-27;
REQ-0006). It uses the guard `seed-dev-users` uses, `KeycloakSettings.is_production`, so
`dev`, `development`, `local`, `test` and `ci` run and anything else, unset included, exits 1
naming `ENV=dev`. The guard runs before a source is read or Keycloak is asked anything, and
covers `--dry-run` and `--check` too: a check has no deployed audience once the sync it checks
has none, and one guard with no exceptions is the one that cannot be argued around. Local
stacks export `ENV=dev` (`taskfile.yaml`, the compose `sync-users` service).

**A community's organization, org roles and org groups come from
`POST /reconcile/{community}`,** which ensures them even when the registry community has no
active member. The registry community must exist first: a community the registry does not
have is `404 community_not_found`, and nothing is created in Keycloak.

**Onboarding calls it, and stays the only caller of the provisioning service.** The call is the
"set up community" step of onboarding's platform-admin registry sync, run before the sync
writes anything else. So `svc-onboarding` holds `provisioning.reconcile` beside
`provisioning.participants.write` — as an optional scope, requested for the reconcile call
only ([ADR-0011](ADR-0011-the-dashboard-writes-registry-data-with-optional-scopes.md)) — and is
still the only client other than `svc-provisioning`
holding a `provisioning.*` scope. The grant lands in `clients.yaml` with the onboarding change
that makes the call, not before: a held scope nothing uses is a scope somebody has to explain.

**Members arrive through onboarding.** Approval calls `PUT /participants/{community}/{key}`,
which files the person in the organization and its `viewers` group.

**A manager is a platform admin's act, by group.** `celine-policies keycloak
set-user-organization <username> --organization <community> --group managers` adds the org
group. **Group names are plural** — `admins`, `managers`, `editors`, `viewers`, the whole of
`ROLE_HIERARCHY` — and the command refuses a group the organization does not have.

**A participant who is also a manager onboards like everyone else.** With the address their
manager account already carries, provisioning finds that account by email and adopts it; the
invitation answers `has_password` and sends nothing. The `viewers` membership that approval
adds must leave the `managers` membership in place. With a different address they get a
second account, and the registry member points at that one.

So the organizations and users level of ADR-0008 has, **on a deployed realm**, these writers:

| What | Writer |
|---|---|
| a REC organization, its org roles and org groups | the provisioning service, `POST /reconcile/{community}`, called by onboarding |
| a participant's account, organization and `viewers` membership | the provisioning service, `PUT /participants/{community}/{key}`, called by onboarding |
| a manager's `managers` (or `admins`) membership | `keycloak set-user-organization`, run by a platform admin |
| a data owner's organization | `keycloak sync-orgs`, unchanged by this record |

## Consequences

- **A deployment job that ran `sync-users` now fails** with the refusal rather than writing.
  The fix is to drop the job, not to set `ENV=dev` on a deployed realm: `ENV` also decides
  whether `keycloak sync` accepts placeholder secrets.
- **`sync-users` loses its deployed audience.** The tempting undo is to "just import the
  managers" from a file on a new community, because it is one command. That is how
  placeholder accounts arrived in the first place; a manager is an account plus one group,
  and both have a writer above.
- **The order is load-bearing:** the registry community, then the registry sync (whose first
  step is the reconcile), then the managers' groups, then onboarding opens. Adding `managers`
  before the organization exists fails, because `set-user-organization` checks that the
  group exists.
- **`test_provisioning_scope_holders.py` changes with the grant.** The sole-holder test stays
  as it is; the test that onboarding holds `participants.write` "and nothing wider" gains
  `provisioning.reconcile` in the change that grants it. `.admin` stays refused.
- **A reconcile is a sweep.** Holding `provisioning.reconcile` lets onboarding provision every
  active member of any community the registry holds, which it can already do one member at a
  time. The platform-admin capability on the registry sync is what keeps that to an explicit
  act.
- **A manager who is not a participant** has no account-creating path in this record: on a
  deployed realm only onboarding and the provisioning service create accounts. How such an
  account is made is still open: it is an operation of the clean start's go-live, not of the
  manager features, and it does not block them — attaching a meter and editing a member's role
  and area need a manager account to exist, not a product path that makes one.
- **Nothing is deleted.** Retiring an old community's accounts is an operation outside the
  product; this repository still has no command that deletes a Keycloak user.
