# ADR-0016 — a non-prod realm holds declared test accounts, written by `sync-test-accounts`

**Date:** 2026-11-05
**Status:** accepted

Refines [ADR-0010](ADR-0010-on-a-deployed-realm-members-arrive-through-onboarding.md) and
[ADR-0008](ADR-0008-each-cli-command-owns-one-level-of-the-realm.md), alongside
[ADR-0015](ADR-0015-an-intermediate-realm-mirrors-prod-members.md). None is superseded: on
prod, members still arrive through onboarding and nothing else; each command still owns one
level; mirrors are untouched. What is added is a second writer of accounts on **non-prod**
realms (dev, staging, preprod): accounts that stand for no person at all.

## Context

Staging and preprod are where the platform is tested, and since 2026-11 where a security
assessment runs against it. Both need sign-ins that hold **each level of authority** the
two-level model of [ADR-0012](ADR-0012-a-platform-administrator-is-a-realm-role.md) knows:
`platform-admin`, and each organization group (`admins > managers > editors > viewers`) in
each kind of organization (a REC, a DSO). An assessor tests what an organization admin can
reach that a viewer cannot, and what nobody outside the organization can reach at all. Some
of those tests are run by people, some by automation that signs in unattended.

What a non-prod realm has today gives none of that on demand:

- **Onboarding** makes participants: one person, the `viewers` group, a community that
  approved them. Not an `admins` of a DSO, and not a dozen of them for a test run.
- **Mirrors** (ADR-0015) are prod's members: `viewers`, no credential, entered by
  impersonation. An assessor signing in with a password, a second factor and a session of
  their own is precisely what impersonation skips.
- **`seed-dev-users`** declares exactly this — accounts with `realm_roles` and
  `organizations: {alias: group}` — but its passwords are in the file, and it refuses unless
  `ENV=dev` (REQ-0006's guard) for that reason.
- **By hand** (`set-user-organization` has no environment guard): repeatable by nobody,
  undone by nobody, and invisible in the realm once done — an assessor's account is
  indistinguishable from a person's.

ADR-0010's reason holds here: no account is made from a file **in place of a person**. A test
account is made from a file **because there is no person**: it is a fixture of the
environment, like a mirror is a trace of prod. What must not happen is that one is mistaken
for a person, survives the test it was made for, or reaches prod.

## Decision

**`celine-policies keycloak sync-test-accounts <file>` converges a non-prod realm's test
accounts on a declaration.** The file is `seed-dev-users`' shape without a password:

```yaml
users:
  - username: test-rec-admin
    organizations: { example-rec: admins }
  - username: test-dso-viewer
    organizations: { example-dso: viewers }
  - username: test-scanner-rec-editor
    organizations: { example-rec: editors }
    password: fixed            # automation signs in with it; default `temporary`
  - username: test-platform-admin
    realm_roles: [platform-admin]
  - username: test-old
    enabled: false
```

**It runs only where the environment says non-prod, by name** (requester, 2026-11-05: "it
must never work on prod"). `ENV` (or `CELINE_KEYCLOAK_ENV`, `CELINE_ENV`, which outrank it)
must be exactly `dev`, `staging` or `preprod`. Anything else is refused before the file is
read or Keycloak is asked anything: `prod`, `production`, a typo, and **unset or empty**,
which the platform rule (`celine.sdk.posture`) reads as hardened. The list names what is
allowed rather than what is refused, so a new or misspelled environment fails closed. An
empty `ENV` is a deployment that forgot to say what it is, and that is the one case where
writing accounts must not be the default.

**A test account is marked.** Every account it makes is in the realm group `/test-accounts`
(no authority, ADR-0012: it says who made the account, as `/member-mirrors` does). By
convention its username starts with `test-`, so an audit log, a token and the admin console
say what it is without a lookup; the command does not enforce the prefix — the group is the
marker.

**It never touches an account it did not make.** An account outside `/test-accounts` is not
written whatever it collides with; a collision is counted and the run exits 2. A mirror is
such an account.

**The declaration is the whole truth about a test account.** Unlike a mirror's memberships,
a test account's realm roles and organization groups are set to exactly what is declared —
added and removed — because nobody else has reason to write them and a test of a downgrade
needs the downgrade to happen. A test account the file no longer names, or names with
`enabled: false`, is **disabled, never deleted**; `users: []` disables them all, which is how
an assessment ends.

**Nothing of a person, and no password in the file.** Placeholder profile as in ADR-0015's
amendment: first name = the username, last name = `test`, e-mail = `<username>@test.invalid`,
verified. A new account's password comes from the environment —
`CELINE_KEYCLOAK_TEST_ACCOUNT_PASSWORD_TEMPLATE` with `{username}` replaced, REQ-0022's
mechanism — and the declaration chooses, per account, what kind it is (requester,
2026-11-05: "automation requires fixed ones"):

- `password: temporary` (the default): the user sets their own at first sign-in. For people.
- `password: fixed`: the password is the template's, with no `UPDATE_PASSWORD`. For
  automation, which cannot answer a form.

The word is a mode, never a value: a declared password is refused as before. A password is
set once, when the account is made, and **never sent again** — except with `--rotate`, which
resets every **fixed** test account's password from the current template, so a changed or
leaked template is replaced in one run. A temporary account is never reset: its user owns it.

A test `platform-admin` meets the admin second factor (REQ-0015) as any holder does, fixed
password or not: this decision does not lift it.

**A missing organization is reported, never created.** Organizations come from the
provisioning reconcile (ADR-0010); a test account declared into one the realm does not have
is skipped, counted, and exits 2.

**It writes with the target realm's admin client**, as `mirror-members` does and for the same
reason: a client of its own would exist in prod's realm too.

So, on a **non-prod** realm, the organizations and users level gains one more writer:

| What | Writer |
|---|---|
| a test account: account, realm roles, organization groups, `/test-accounts` | `keycloak sync-test-accounts`, from the deployment's declaration |

## Why this does not contradict "members arrive through onboarding"

A test account is not a member. It is in no registry community, stands for nobody, and has
nothing an onboarding would have collected. ADR-0010 keeps a file from **replacing** a person;
here no person is replaced, and on prod the command refuses to run.

## Consequences

- **A test account has Keycloak authority and no registry data.** Mock registry members are
  the REC registry's, through its own import (requester, 2026-11-05), not this repository's:
  this command writes Keycloak only. A deployment that needs both runs both, and pairs them by
  username.
- **`seed-dev-users` stays** for local development, where its public passwords are the point.
  `sync-test-accounts` also runs with `ENV=dev`; merging the two is left for later.
- **Running it is the deployment's.** Which environments declare test accounts, and whether
  the policies shell runs the command after `bootstrap` or a Job does, is decided where the
  declaration lives, not here.
- **A fixed password is a standing credential on a reachable realm.** It lives in the
  deployment's secrets, not in a file; `--rotate` replaces it and `users: []` ends it.
  Noticing one is left is not automated.
- **A host guard was considered and not taken.** `mirror-members` also refuses the source
  issuer's host because it has a source to compare with; this command has none, and the
  named-environment list already fails closed.
- **The tempting undo** is relaxing `seed-dev-users`' guard to "not prod". It would put
  passwords in a deployed declaration and leave its accounts unmarked.
