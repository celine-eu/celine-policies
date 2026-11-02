# ADR-0015 — an intermediate realm holds mirrors of prod's members, written by `mirror-members`

**Date:** 2026-11-02
**Status:** accepted

Refines [ADR-0010](ADR-0010-on-a-deployed-realm-members-arrive-through-onboarding.md) and
[ADR-0008](ADR-0008-each-cli-command-owns-one-level-of-the-realm.md). Neither is superseded:
on prod, members still arrive through onboarding and nothing else; each command still owns
one level. What is added is a writer of accounts on **intermediate** realms (staging,
preprod), which are deployed realms and which ADR-0010 did not tell apart from prod.

## Context

Staging and preprod are internal development instances fed with the pipelines' outputs, and
those outputs are computed from prod's members only. Settlement, points and the webapp key a
person by their Keycloak `sub`. For an intermediate realm to show prod's outputs to anybody,
it needs accounts whose id **is** prod's `sub` for each member, and nothing of the person
behind it: prod's member data must not be copied into a less protected environment.

ADR-0010 says that on a deployed realm members arrive through onboarding. On an intermediate
realm that produces native accounts nobody's outputs are computed for, and a person would
have to onboard twice, giving their e-mail and name to a non-prod system.

Three facts shaped the decision:

- `POST /users` assigns its own id; `POST /partialImport` keeps the `id` it is given
  (measured on Keycloak 26.7.3, 2026-10-30). Partial import needs `manage-realm`.
- Keycloak drops a user attribute the realm's user profile does not declare, and no realm
  here declares one. A user attribute cannot mark an account as a mirror.
- Fine-grained admin permissions can grant `impersonate-members` over one realm group to a
  user policy naming accounts.

## Decision

**`celine-policies keycloak mirror-members` writes mirrors of a source realm's members into
an intermediate realm.** It reads prod's registry (`GET /admin/export/mirror`, scope
`rec-registry.mirror`, client `svc-member-mirror` of prod's realm) or the same document from a
file, and for every member with an account subject converges one account:

- id = the subject, username = the member key, enabled while the member is active;
- no personal e-mail or name, no credential or attribute; a placeholder profile instead
  (amended 2026-11-02, below);
- in the community's organization (alias = community key) and its `viewers` group, as
  provisioning files a participant;
- in the realm group `/member-mirrors`, which marks it as a mirror and carries the source
  issuer as its `celine_mirror` attribute.

**It never runs on prod.** It refuses `ENV` `prod` or `production`, and `ENV` unset (which
reads as `prod`), and a target Keycloak whose host is the source issuer's host. The guard runs
before the source is read or Keycloak is asked anything.

**It never touches an account it did not make.** An account outside `/member-mirrors` is not
written whatever it collides with; a collision is counted and the run exits 2. A mirror whose
member left prod or went inactive is **disabled, never deleted**. Organization memberships are
added, never removed.

**The team enters a mirror by impersonation.** With `--impersonator` (or
`CELINE_MEMBER_MIRROR_IMPERSONATORS`), the command keeps a user policy naming those accounts
and a `Groups` permission on `/member-mirrors` with `impersonate-members`, `view` and
`view-members`, and nothing that writes. Their names are `celine-member-mirror:*`, outside the
`celine-policies:` prefix `keycloak sync` reads and prunes. The list is the deployment's. The
named accounts also need `query-users` and `query-groups` (realm-management): without any
realm-management role the admin console refuses them (staging, 2026-11-02), and those two
open it without widening what the permission lets them see. The command checks them and
does not grant them (amended 2026-11-02, below).

**It writes with the target realm's admin client** (`celine-admin-cli`, the credential the
policies shell already holds), not with a client of its own: partial import needs
`manage-realm`, organization membership `manage-organizations` and the user writes
`manage-users`, which is `svc-provisioning`'s realm-wide set. A dedicated client would be a
second realm administrator under another name, and `clients.yaml` is one declaration for every
environment, so it would also exist in prod's realm, where the command must never run.

So, on an **intermediate** realm, the organizations and users level of ADR-0010 gains one
writer:

| What | Writer |
|---|---|
| a mirror of a prod member: account, organization, `viewers`, `/member-mirrors` | `keycloak mirror-members`, from prod's registry |
| who may impersonate a mirror | `keycloak mirror-members --impersonator`, the deployment's list |

## Why this does not contradict "members arrive through onboarding"

ADR-0010 exists so that no account is made from a file rather than from a person. A mirror is
made from prod, where that person did onboard: the account is the trace of an onboarding that
happened, not a substitute for one. On prod nothing changes and the command refuses to run.
`sync-users` and the YAML seed stay local development (REQ-0006).

## Consequences

- **An intermediate realm's own onboarding keeps working** for a community no flow reads; its
  accounts are outside `/member-mirrors` and the mirror never touches them.
- **A changed member key in prod is reported, not renamed**: the mirror keeps its old
  username until someone decides. A key reassigned to another subject is reported too.
- **A stopped mirror freezes the intermediate realm's membership.** The job needs a freshness
  check like the pipeline mirrors.
- **The source issuer is part of the mirror group.** Pointing a realm at another source means
  a new group, not adopting the old one: the command refuses a `/member-mirrors` that carries
  another source.
- **The tempting undo** is a user attribute as the marker, because it reads more naturally.
  Keycloak drops it without a word unless the user profile declares it, and a later admin `PUT`
  of the user can lose it; a group membership is kept and is also what the impersonation grant
  is scoped to.

## Amendment 2026-11-02 — a placeholder profile

The realm's user profile requires an e-mail, a first and a last name. On staging, an
impersonation of a mirror carrying none of them stopped at Keycloak's "Update Account
Information" form (`VERIFY_PROFILE`), before the webapp. A mirror now carries placeholders
made from its own key: first name = the key, last name = `mirror`, e-mail =
`<key>@mirror.invalid` (`.invalid` is reserved, RFC 2606, and never delivers), verified so
that no `VERIFY_EMAIL` follows. A key unfit for an address or a name uses the subject. The
decision reads "no **personal** e-mail or name": nothing of the person is written, as before.
Mirrors made earlier get the placeholders on the next run.

Rejected: relaxing the realm's user profile (or `VERIFY_PROFILE`) on the intermediate realm.
It changes the invitation path of the realm's own accounts and moves the intermediate realm
away from prod's.

## Amendment 2026-11-02 — the console roles are checked, not granted

celine-policies 1.12.0 had `mirror-members` assign `query-users` and `query-groups` to each
impersonator. On staging Keycloak answered 403 to that grant (`POST
…/users/<id>/role-mappings/clients/<realm-management>`) although `celine-admin-cli` holds
`manage-users` and both roles, in its token and on its service account; the job failed
every run and its registry half stopped. Admin roles for people are not a scheduled job's
to give anyway. The command now only checks them: an impersonator missing either is
counted as `impersonators_without_console_roles` and the run exits 2 (the CronJob's
registry half still runs). A master admin assigns them once, from the console. Which
Keycloak check refused the grant was not investigated.
