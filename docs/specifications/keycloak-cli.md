# Keycloak CLI

The `celine-policies keycloak` commands, where a decision fixed what a command may do. The
commands are described in [architecture.md](../architecture.md) and
[deployment.md](../deployment.md).

---

### REQ-0006 — `sync-users` runs only in a development environment

`celine-policies keycloak sync-users` **refuses to run unless the environment names a
development one**: `ENV` (or `CELINE_KEYCLOAK_ENV`, `CELINE_ENV`, which outrank it) is
exactly `dev` — the guard `seed-dev-users` uses. Unset, `prod`, `staging`, `development`,
`local`, `test`, `ci` or any other value exits `1` with a message that names `ENV=dev`.

> Until 2026-10 `development`, `local`, `test` and `ci` relaxed it too. The platform rule
> (`celine.sdk.posture`) is that only `dev` relaxes, and ADR-0010's wording "`ENV=dev`" now
> means exactly that value.

The refusal comes **before a source is read or Keycloak is asked anything**, and holds for
`--dry-run` and `--check` too.

On a deployed realm members arrive through onboarding and a community's organization through
the provisioning reconcile; the YAML seed and `sync-users` are local development
([ADR-0010](../decisions/ADR-0010-on-a-deployed-realm-members-arrive-through-onboarding.md)).

---

The next three fix the realm's authority model: **exactly two levels**. The realm role
`platform-admin` is the only platform-wide grant; an organization's own groups
(`admins > managers > editors > viewers`) are valid only inside that organization. Realm
groups carry no authority at all, and a realm group still present in a token grants nothing
(requester, 2026-10-03; [ADR-0012](../decisions/ADR-0012-a-platform-administrator-is-a-realm-role.md)).

### REQ-0011 — the platform-wide grant is the realm role `platform-admin`, held directly

`celine-policies keycloak bootstrap` converges, on every run and from any starting realm:

- **The realm role `platform-admin` exists.** `platform.yaml` declares it under
  `platform_admin.role` and refuses any other name: it is `celine-sdk`'s
  `PLATFORM_ADMIN_ROLE`, the name every service reads from `realm_access.roles`.
- **It is held by the operator realm admin** (`CELINE_KEYCLOAK_REALM_ADMIN_USERNAME`) **and by
  every user `platform_admin.users` lists**, as a direct role mapping. The list is empty in the
  image; a deployment names its own in its overlay. A listed user who does not exist yet is
  reported and is not a change.
- **It is held directly, never through anything shared.** A mapping of the role onto a realm
  group is removed, and so is the role inside the realm's default roles or any other composite
  realm role: each would hand the platform grant to everyone in it. (A realm role mapped onto an
  organization's group — only the Organization API can — reaches no member's token on 26.7.3,
  and Keycloak does not list it; bootstrap leaves it alone.)
- A user who holds the role directly but is not declared keeps it and is **reported** by
  name; bootstrap does not revoke a grant an administrator gave by hand.

`--check` fails while anything above would change.

### REQ-0012 — bootstrap removes the retired realm groups and realm roles

`platform.yaml` names under `retired` the realm groups `/admins`, `/managers`, `/editors`,
`/viewers` and the realm roles `admin`, `manager`, `editor`, `viewer`. On every run
`bootstrap` **deletes each one the realm holds**, with its memberships and its group-to-role
mappings, and leaves every other group and role alone:

- from any starting state — all present, some present, none present — and a second run
  changes nothing;
- whether or not the groups still carry their roles, and whatever users are in them;
- only top-level realm groups: an organization's own group of the same name (whose path is
  also `/admins`) is never touched;
- not gated on `--allow-destructive`: the removal is the declaration, and a deployment must
  converge to it whatever it held before;
- the retired names may not include `platform-admin` or a Keycloak built-in role
  (`offline_access`, `uma_authorization`, `default-roles-*`).

`role_groups`, which declared the old groups, is no longer accepted.

### REQ-0013 — no token carries a realm `groups` claim; a sign-in client carries `roles`

After `celine-policies keycloak sync` (a full run, not `--additive`):

- **No mapper in the realm writes a top-level `groups` claim**: not the `groups` client
  scope's group-membership mapper (`full.path: true`), not a client-level group-membership
  mapper such as the one `oauth2_proxy` carried (`full.path: false`), and not
  `microprofile-jwt`'s realm-role mapper writing roles into `groups`. Each is deleted, and the
  `groups` client scope itself is removed from every client and from the realm.
- **Organization groups reach a token in exactly one place**, `organization.<alias>.groups`,
  through the `organization` scope's organization-group-membership mapper.
- **Every client that declares `browser:` (signs people in) holds `roles` as a default
  scope**, so its tokens carry `realm_access.roles`. A `clients.yaml` with a browser client
  that does not is refused at load time. Service-account clients are unaffected.

`sync --additive` removes none of these; it names each mapper and assignment it kept.

---

### REQ-0015 — outside dev, a platform admin signs in with a second factor

`celine-policies keycloak bootstrap` owns the realm's browser sign-in flow (it is platform
level, [ADR-0008](../decisions/ADR-0008-each-cli-command-owns-one-level-of-the-realm.md);
[ADR-0013](../decisions/ADR-0013-bootstrap-owns-the-admin-second-factor.md)).
`CELINE_KEYCLOAK_ADMIN_MFA_REQUIRED` decides it; **unset, it is on unless the environment is
exactly `dev`** (`ENV`, `CELINE_ENV` or `CELINE_KEYCLOAK_ENV`, the guard REQ-0006 uses).
Requester, 2026-10-04.

When it is on, on every run and from any starting realm (no such flow, the flow a realm import
declared, the flow with a condition on the retired role `admin`, a flow of another shape under
the same name), `bootstrap` converges:

- **the flow `browser-admin-second-factor`, bound as the realm's browser flow.** Everyone signs
  in with a password, or a passkey from the same page; a user holding the realm role
  `platform-admin` who did not use a passkey must then give a one-time code (TOTP) or a
  recovery code, and one who has neither enrols both before the sign-in completes. A user
  without the role is never asked. The condition tests `platform-admin` and nothing else.
- **its shape exactly**, the one measured on Keycloak 26.7.3: a flow of another shape under that
  name is replaced; a wrong condition value (a role, the credential, the sub-flow checked) is
  corrected in place.
- **the required actions `CONFIGURE_TOTP` and `CONFIGURE_RECOVERY_AUTHN_CODES` are enabled**;
  without them the enrolment cannot run.
- it refuses, before any write, a Keycloak that does not list every authenticator the flow
  names: an unknown provider id fails every browser sign-in, for every user.

When it is off, the realm's browser flow is Keycloak's own `browser`. The custom flow, if
present, stays in place, unbound. Outside dev, turning it off on a realm that has it bound is
destructive and needs `--allow-destructive`.

In either case, a `Condition - user role` in any other flow that names a role `retired` lists
(`admin`, …) is repointed to `platform-admin`: the retired role is deleted (REQ-0012), and a
condition on it would silently match nobody.

`--check` fails while anything above would change. The flow is the browser flow only: the
password grant (`directAccessGrantsEnabled`) does not run it.

---

### REQ-0016 — `bootstrap` reaches the master realm through its own client, and hardens it outside dev

The master realm holds the Keycloak-wide administrator, the account that configures the
platform, and Keycloak is public (requester, 2026-10-04;
[ADR-0014](../decisions/ADR-0014-bootstrap-hardens-the-master-realm-through-its-own-client.md)).
`celine-policies keycloak bootstrap`, on every run:

1. **Signs in to master with its dedicated client first.** That client is
   `svc-celine-policies-bootstrap` (`CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_ID`), with the secret
   `CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET`, a configured value: the deployment takes it from
   its secrets. Only when that sign-in fails (the client does not exist yet, or holds another
   secret) does it sign in as the master admin user (`CELINE_KEYCLOAK_ADMIN_USER` /
   `_PASSWORD`).
2. **Converges the client in master**: confidential, enabled, service account on, standard
   flow, implicit flow and direct access grants off; its secret set to the configured value;
   and holding master's realm role `admin`. Nothing narrower can do `bootstrap`'s work: in a
   realm with fine-grained admin permissions (`adminPermissionsEnabled`, which `platform.yaml`
   declares) only a master `admin` may grant the admin CLI client its realm-management roles
   (measured on 26.7.3, ADR-0014). The secret, never generated and never printed, is what
   protects it.
3. **Switches to that client's `client_credentials` token for everything else**, the target
   realm included, after checking the token is the client's (`azp`, issued by master). The
   other commands (`sync`, …) sign in as that client too, when its secret is set and the admin
   CLI client's is not, before trying the admin user.
4. **Outside dev, then hardens master**, only with that token:
   - **brute-force detection**: `bruteForceProtected` as for the platform realm
     (`CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED`, on unless `ENV=dev`), with the same declared
     tuning (`permanentLockout`, `failureFactor`, `waitIncrementSeconds`,
     `quickLoginCheckMilliSeconds`, `minimumQuickLoginWaitSeconds`, `maxFailureWaitSeconds`
     from `platform.yaml` and its overrides);
   - **a second factor for every master administrator** (`CELINE_KEYCLOAK_ADMIN_MFA_REQUIRED`,
     on unless `ENV=dev`): the browser flow `browser-admin-second-factor` of REQ-0015, without
     the organization step and conditioned on master's realm role `admin`, bound as master's
     browser flow; and every user holding `admin` directly who has no one-time code yet (a
     client's service account excepted, the bootstrap client's own included) gets the
     required action `CONFIGURE_TOTP`, so a password alone no longer obtains a token
     through `admin-cli` either. The second factor is enrolled at that administrator's next
     sign-in to the admin console.

   **The hardening refuses to run on any other token** — the master admin user's, the admin
   CLI client's, or a client token this run did not obtain and check itself — before any
   write. An administrator's own token could otherwise turn on the factor that cuts its own
   access off mid-run.

**Outside dev the client's secret is required**: without
`CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET`, or with one shorter than 32 characters,
`bootstrap` exits `1` before Keycloak is asked anything, `--dry-run` and `--check` included.
After the first run the master admin's password grant fails, which is expected: every later
run signs in as the client.

**In dev** (`ENV=dev`, defaults) nothing changes: the client is optional (managed when the
secret is set), master is not hardened, and with neither switch on the master realm's
settings and flows are not touched at all.

Every step above is idempotent and converges from any start: no client, a client with
another secret or flags or missing roles, a master realm with brute force off or tuned
differently, Keycloak's own `browser` flow bound, or the flow of another shape. Turning
either switch off on a hardened master is destructive and needs `--allow-destructive`
outside dev. `--check` fails while anything above would change. Recovery when the client
is lost is Keycloak's own `kc.sh bootstrap-admin`.

---

### REQ-0020 — `sync` and `bootstrap` write client secrets to disk only when asked, readable by their owner only

`celine-policies keycloak sync` records the secrets of the clients it created or updated, and
`celine-policies keycloak bootstrap` the secret of the admin CLI client (`celine-admin-cli`) it
created or refreshed, in a secrets file only when the run asks for it:

- **`--secrets-file PATH`**, or **`CELINE_KEYCLOAK_SECRETS_FILE`** set: the run writes that path.
- **Neither, under `ENV=dev`**: the run writes `.client.secrets.yaml` in the working directory, as
  before.
- **Neither, any other `ENV`, unset included**: the run writes no file and says so. `sync`
  prints how many clients' secrets it did not record and how to ask; `bootstrap` prints how to
  ask, and where the secret can be read instead (the realm's admin console, the client's
  Credentials tab). Outside dev the other commands need no copy of it either: they sign in as the
  bootstrap client when `CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET` is set and the admin CLI
  client's secret is not (REQ-0016).
- `--dry-run` and `--check` write nothing, asked or not.

Every write of the file — `sync`'s and `bootstrap`'s, through the one merging writer — leaves it
mode `0600`, narrowing a file an earlier run left wider. The secrets a `sync` applies are the
deployment's own inputs (`${SVC_…_SECRET}`), so nothing outside dev needs them back from disk; the
one reader of `sync`'s entries is `sync-users --from-registry`'s last fallback for the registry
client's secret, a dev-only command (REQ-0006).


---

### REQ-0021 — `mirror-members` keeps mirrors of prod's members on an intermediate realm, and never runs on prod

`celine-policies keycloak mirror-members` reads the member mirror export of a source registry
(`GET /admin/export/mirror`, scope `rec-registry.mirror`, client `svc-member-mirror` of the
source realm, or the same JSON from `--from-file`) and converges the target realm on it
([ADR-0015](../decisions/ADR-0015-an-intermediate-realm-mirrors-prod-members.md)):

- **One mirror per member with an account subject:** id = the subject (lower-case UUID),
  username = the member key (lower-cased by Keycloak), enabled exactly while the member's
  status is `active`; created by partial import with `ifResourceExists: FAIL`. A subject in
  two communities is one mirror in both.
- **Nothing personal is written:** the representation carries `id`, `username`, `enabled`,
  `groups` and a placeholder profile only — no credential, no attribute, nothing of the
  person. The placeholder profile satisfies the realm's user profile (e-mail, first and last
  name required): first name = the username, last name = `mirror`, e-mail =
  `<username>@mirror.invalid`, `emailVerified` true; a username unfit for an address or a
  name uses the subject instead. Without it an impersonation stops at `VERIFY_PROFILE`.
  A mirror whose profile differs (made earlier, or edited by hand) is put back to it, and
  counted as `profile_written`.
- **A member without a subject gets no account**, and is counted.
- **Membership:** the community's organization (alias = community key) and its `viewers`
  group, and the realm group `/member-mirrors`, which carries the source issuer as attribute
  `celine_mirror`. A `/member-mirrors` without that value is refused (exit 1).
- **Only mirrors are written.** An account outside `/member-mirrors` is never written, even
  when it holds the member's username or id; a username held by another mirror, a changed key,
  a subject under two keys or a key under two subjects, and a community with no organization
  (or no `viewers` group) are skipped and counted.
- **Disable, never delete:** a mirror whose subject is gone from the export or no longer active
  is disabled. No command deletes a user; organization memberships are not removed.
- **Idempotent:** a second run with the same export writes nothing. `--dry-run` writes nothing
  and reports the counts a run would.
- **Impersonation:** with `--impersonator NAME` (repeatable) or
  `CELINE_MEMBER_MIRROR_IMPERSONATORS` (space-separated), a user policy
  `celine-member-mirror:impersonators` names exactly those accounts and a `Groups` permission
  `celine-member-mirror:impersonate` on `/member-mirrors` grants them `impersonate-members`,
  `view` and `view-members`, nothing else. Each named account also needs the realm-management
  roles `query-users` and `query-groups` (the admin console refuses an account with no
  realm-management role; searches run filtered by the permission above). The command **checks
  them and never grants them**: an account missing either is counted as
  `impersonators_without_console_roles`, and a master admin assigns them once. A name with no
  account is counted; a mirror is never an impersonator. No list: the permission is left as it
  is.
- **Refusals, before the source is read or Keycloak is asked anything:** `ENV` (or
  `CELINE_KEYCLOAK_ENV`, `CELINE_ENV`) `prod` or `production`, or unset; a target Keycloak whose
  host is the source issuer's; no `--source-issuer`; both or neither source; a registry source
  without `CELINE_MEMBER_MIRROR_SOURCE_CLIENT_SECRET`.
- **Output is counts** (and the community keys without an organization), never a member's key,
  subject or anything else of a member.
- **Exit codes:** `0` converged; `1` refused or failed; `2` ran, but a member could not be
  mirrored (a skip above other than a missing subject, or an impersonator not found, refused
  or without the console roles).

The source client holds `rec-registry.mirror` alone, and its token names `svc-rec-registry`
and `oauth2_proxy` (the source's API gateway). The target is written with the target realm's
admin client.

### REQ-0022 — `bootstrap` creates a declared platform-admin account once, and never rewrites it

A `platform_admin.users` entry is a username (REQ-0011: granted once the account exists,
reported until then) or an **account**, `{username, email, first_name, last_name}`, in
`platform.yaml` or a deployment's overlay. For an account, `celine-policies keycloak bootstrap`:

- **creates it when the realm has no such user**, enabled, with the email marked verified, the
  declared names, and a **temporary** password the user must change at first sign-in; then
  grants `platform-admin` directly. The admin second factor follows from the role (REQ-0015).
- takes the temporary password from the environment, never from a file:
  `CELINE_KEYCLOAK_ADMIN_TEMP_PASSWORD_TEMPLATE` with `{username}` replaced. A template without
  `{username}` is refused; unset, the run is refused before any write. The variable is outside
  the `CELINE_KEYCLOAK_PLATFORM_` prefix, which holds realm-setting overrides only.
- **never rewrites an existing account**: no password is sent, the email is not changed, and a
  disabled account is not enabled again. A disabled account and an email that differs from the
  declaration are reported.

A declaration names no password; an account with a `password` key is refused.


### REQ-0023 — `sync-test-accounts` keeps declared test accounts on an intermediate realm, and never runs on prod

> **Proposed** ([ADR-0016](../decisions/ADR-0016-an-intermediate-realm-holds-declared-test-accounts.md)).
> Not implemented; nothing verifies it yet.

`celine-policies keycloak sync-test-accounts <file>` converges the target realm's test
accounts on the declaration in `<file>`:

- **The declaration:** `users:`, a list (empty allowed) of `{username, realm_roles?,
  organizations?, enabled?}`. `username` starts with `test-`; `realm_roles` may name only
  `platform-admin`; `organizations` maps an organization alias to one of its groups (`admins`,
  `managers`, `editors`, `viewers`). A `password`, an e-mail, a name or any other key is
  refused, as is a username declared twice. The whole file is checked before anything is
  written.
- **One account per declared user,** created when the realm has none: enabled (unless
  `enabled: false`), in the realm group `/test-accounts`, with the placeholder profile first
  name = the username, last name = `test`, e-mail = `<username>@test.invalid`,
  `emailVerified` true, and a **temporary** password from
  `CELINE_KEYCLOAK_TEST_ACCOUNT_PASSWORD_TEMPLATE` with `{username}` replaced. A template
  without `{username}` is refused; unset, a run that would create an account is refused
  before any write. An existing test account's password is never sent.
- **Exactly the declared authority:** a test account holds `platform-admin` exactly when
  declared, and in each organization exactly the declared group; a membership or group not
  declared is removed. A profile that differs from the placeholder is put back.
- **Only test accounts are written.** An account outside `/test-accounts` is never written,
  even when it holds a declared username; it is counted. A declared organization the realm
  does not have (or one without the declared group) is skipped and counted.
- **Disable, never delete:** a test account the file does not name, or names with
  `enabled: false`, is disabled. No user is deleted.
- **Idempotent:** a second run with the same file writes nothing. `--dry-run` writes nothing
  and reports what a run would.
- **Refusals, before the file is read or Keycloak is asked anything:** `ENV` (or
  `CELINE_KEYCLOAK_ENV`, `CELINE_ENV`) `prod` or `production`, or unset.
- **Output is usernames and counts**, never a password.
- **Exit codes:** `0` converged; `1` refused or failed; `2` ran, but a declared account could
  not be converged (a collision, a missing organization or group).

The target is written with the target realm's admin client.
