"""Declared test accounts on a non-prod realm (REQ-0023, ADR-0016).

A test account stands for no person: it is a fixture of a non-prod environment (dev,
staging, preprod), declared by the deployment, holding a chosen level of authority — the
realm role `platform-admin`, and one group in each declared organization — so that the
platform and a security assessment can be tested with real sign-ins.

## The declaration

`seed-dev-users`' shape without a password::

    users:
      - username: test-rec-admin
        organizations: { example-rec: admins }
      - username: test-scanner
        organizations: { example-rec: editors }
        password: fixed          # default `temporary`
      - username: test-platform-admin
        realm_roles: [platform-admin]
      - username: test-old
        enabled: false

`password` is a **mode**, never a value. The value comes from
`CELINE_KEYCLOAK_TEST_ACCOUNT_PASSWORD_TEMPLATE` with `{username}` replaced, and is sent
only when the account is made, and with `--rotate` to the enabled fixed accounts.

## How a test account is told from everyone else

By membership of the realm group `/test-accounts`, which the account is created in (in the
same request, so no account is ever left outside it). The group carries the attribute
`celine_test_accounts`, and a group of that name without it is refused rather than adopted:
adopting it would make its members this command's to disable. The group grants nothing
(realm groups carry no authority, ADR-0012).

## How a fixed password is told from a temporary one

The password credential of a fixed account carries the `userLabel` `FIXED_LABEL`; a
temporary account's carries none. Keycloak keeps no other trace of the mode once a temporary
password was changed, and an attribute on the user would be dropped by the user profile. A
declared mode that differs from the account's is reported, not applied: changing it means
sending a password, which only creation and `--rotate` do (and `--rotate` only to fixed).

## What is never done

- An account outside `/test-accounts` is never written, whatever it collides with.
- No user is deleted: a test account the file no longer names, or names `enabled: false`, is
  disabled. A `MANAGED` organization membership is never removed (Keycloak would delete the
  account with it); this command never makes one.
- No organization or organization group is created: one the realm lacks is reported.
- No password is printed. The report is usernames and counts.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from celine.sdk.auth import PLATFORM_ADMIN_ROLE

from celine.policies.cli.keycloak.client import ROLE_HIERARCHY, KeycloakError
from celine.policies.cli.keycloak.member_mirror import placeholder_profile, placeholder_safe

#: The values of ENV this command runs under, and only these (case-insensitive). An
#: allow-list: `prod`, a typo, a new environment, unset and empty all fail closed.
ALLOWED_ENVS = ("dev", "staging", "preprod")

#: The realm group every test account is in, and only test accounts.
TEST_ACCOUNTS_GROUP = "/test-accounts"
#: The attribute that says the group is this command's.
TEST_ACCOUNTS_MARKER = "celine_test_accounts"
TEST_ACCOUNTS_MARKER_VALUE = "sync-test-accounts"

#: The placeholder profile: first name = the username, and these.
TEST_LAST_NAME = "test"
TEST_EMAIL_DOMAIN = "test.invalid"

#: The `userLabel` on a fixed account's password credential.
FIXED_LABEL = "celine-test-account:fixed"

TEMPORARY, FIXED = "temporary", "fixed"
PASSWORD_MODES = (TEMPORARY, FIXED)

#: The realm roles a test account may hold: the platform-wide grant, and nothing else.
TEST_REALM_ROLES = frozenset({PLATFORM_ADMIN_ROLE})

_FIELDS = {"username", "realm_roles", "organizations", "password", "enabled"}

#: The counts a run reports, in print order.
COUNTS = (
    "declared",
    "created",
    "enabled",
    "disabled",
    "profile_written",
    "realm_roles_added",
    "realm_roles_removed",
    "organizations_joined",
    "organizations_left",
    "groups_added",
    "groups_removed",
    "passwords_rotated",
    "unchanged",
    "unmanaged_collisions",
    "organization_missing",
    "group_missing",
    "password_refused",
    "mode_drift",
    "managed_memberships",
)
#: The counts that mean a declared account could not be converged: the run exits 2.
ATTENTION = frozenset(
    {
        "unmanaged_collisions",
        "organization_missing",
        "group_missing",
        "password_refused",
        "mode_drift",
        "managed_memberships",
    }
)


class TestAccountsRefused(RuntimeError):
    """The run must not write this realm, or cannot without a missing input."""

    __test__ = False  # not a pytest class, whatever its name


@dataclass(frozen=True)
class TestAccount:
    """One declared test account."""

    __test__ = False

    username: str
    realm_roles: frozenset[str] = frozenset()
    organizations: tuple[tuple[str, str], ...] = ()
    password: str = TEMPORARY
    enabled: bool = True

    @property
    def profile(self) -> dict[str, Any]:
        return placeholder_profile(
            self.username, self.username, last_name=TEST_LAST_NAME, email_domain=TEST_EMAIL_DOMAIN
        )


@dataclass
class TestAccountsReport:
    """What a run did (or, dry, would do): usernames and counts, never a password."""

    __test__ = False

    counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(COUNTS, 0))
    changes: list[tuple[str, str]] = field(default_factory=list)
    missing_organizations: set[str] = field(default_factory=set)
    group_created: bool = False

    def add(self, name: str, n: int = 1) -> None:
        self.counts[name] += n

    def note(self, username: str, what: str) -> None:
        self.changes.append((username, what))

    @property
    def needs_attention(self) -> bool:
        return any(self.counts[name] for name in ATTENTION)


# ---------------------------------------------------------------------------
# Where it may run
# ---------------------------------------------------------------------------


def refusal(env: str | None) -> str | None:
    """Why this run must not write any realm, or None. Checked before anything is read."""
    value = (env or "").strip()
    if value.lower() in ALLOWED_ENVS:
        return None
    shown = f"'{value}'" if value else "unset or empty"
    return (
        f"sync-test-accounts runs only where ENV is {', '.join(ALLOWED_ENVS)}; ENV is "
        f"{shown}. It never runs on prod."
    )


# ---------------------------------------------------------------------------
# The declaration
# ---------------------------------------------------------------------------


def parse_test_accounts(data: Any, source: str = "declaration") -> list[TestAccount]:
    """Check the whole declaration and reduce it to `TestAccount`s. Refused whole."""
    if not isinstance(data, dict) or set(data) != {"users"} or not isinstance(data["users"], list):
        raise ValueError(f"{source}: expected exactly a `users:` list (it may be empty)")
    accounts: list[TestAccount] = []
    seen: set[str] = set()
    for i, user in enumerate(data["users"]):
        where = f"{source}: users[{i}]"
        if not isinstance(user, dict):
            raise ValueError(f"{where} must be a mapping")
        unknown = set(user) - _FIELDS
        if unknown:
            raise ValueError(
                f"{where} has key(s) {sorted(unknown)}; a test account declares only "
                f"{sorted(_FIELDS)} (no e-mail, name or password: the profile is a placeholder)"
            )
        username = user.get("username")
        if not isinstance(username, str) or not placeholder_safe(username):
            raise ValueError(
                f"{where}.username must be lower-case letters, digits, '.', '_' or '-' "
                f"(it is also the placeholder e-mail's local part), got {username!r}"
            )
        if username in seen:
            raise ValueError(f"{where}.username {username} is declared twice")
        seen.add(username)

        roles = user.get("realm_roles", []) or []
        if not isinstance(roles, list) or not set(roles) <= TEST_REALM_ROLES:
            raise ValueError(
                f"{where}.realm_roles may name only {sorted(TEST_REALM_ROLES)}, got {roles!r}"
            )
        orgs = user.get("organizations", {}) or {}
        if not isinstance(orgs, dict) or not all(
            isinstance(alias, str) and alias and group in ROLE_HIERARCHY for alias, group in orgs.items()
        ):
            raise ValueError(
                f"{where}.organizations must map an organization alias to one of "
                f"{ROLE_HIERARCHY}, got {orgs!r}"
            )
        mode = user.get("password", TEMPORARY)
        if mode not in PASSWORD_MODES:
            raise ValueError(
                f"{where}.password is a mode, {' or '.join(PASSWORD_MODES)}; a password is "
                f"never declared (it comes from CELINE_KEYCLOAK_TEST_ACCOUNT_PASSWORD_TEMPLATE)"
            )
        enabled = user.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError(f"{where}.enabled must be true or false, got {enabled!r}")
        accounts.append(
            TestAccount(
                username=username,
                realm_roles=frozenset(roles),
                organizations=tuple(sorted(orgs.items())),
                password=mode,
                enabled=enabled,
            )
        )
    return accounts


def load_test_accounts(path: Path) -> list[TestAccount]:
    """Read and check the declaration file."""
    try:
        data = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as e:
        raise ValueError(f"{path}: {e}") from e
    return parse_test_accounts(data, str(path))


# ---------------------------------------------------------------------------
# Converging the realm
# ---------------------------------------------------------------------------

#: The password for a username, or None when the template is unset.
PasswordFor = Callable[[str], "str | None"]
_Op = Callable[[], Awaitable[None]]


def _password_refused(e: KeycloakError) -> bool:
    """Whether Keycloak refused a password (its policy), rather than failed."""
    return e.status_code == 400


async def _marker_group(kc: Any) -> tuple[str | None, dict[str, dict[str, Any]]]:
    """The group's id and its members by username; refuses a group this command did not make."""
    group = await kc.get_group_by_path(TEST_ACCOUNTS_GROUP)
    if group is None:
        return None, {}
    full = await kc.get_group(group["id"])
    if (full.get("attributes") or {}).get(TEST_ACCOUNTS_MARKER) != [TEST_ACCOUNTS_MARKER_VALUE]:
        raise TestAccountsRefused(
            f"the realm has a group {TEST_ACCOUNTS_GROUP} without "
            f"{TEST_ACCOUNTS_MARKER}={TEST_ACCOUNTS_MARKER_VALUE}; it was not made by "
            f"sync-test-accounts, and its members are not taken over"
        )
    members = await kc.get_group_members(group["id"])
    return group["id"], {(u.get("username") or "").lower(): u for u in members}


class _Organizations:
    """Alias -> (organization id, {group name: group id}) or None, read once."""

    def __init__(self, kc: Any):
        self._kc = kc
        self._cache: dict[str, tuple[str, dict[str, str]] | None] = {}

    async def get(self, alias: str) -> tuple[str, dict[str, str]] | None:
        if alias not in self._cache:
            org = await self._kc.get_organization_by_alias(alias)
            if org is None:
                self._cache[alias] = None
            else:
                groups = {g["name"]: g["id"] for g in await self._kc.list_org_groups(org["id"]) if g.get("name")}
                self._cache[alias] = (org["id"], groups)
        return self._cache[alias]

    async def resolve(
        self, account: TestAccount, report: TestAccountsReport
    ) -> dict[str, tuple[str, str]] | None:
        """alias -> (org id, declared group id), or None (counted) when any is missing."""
        found: dict[str, tuple[str, str]] = {}
        ok = True
        for alias, group in account.organizations:
            org = await self.get(alias)
            if org is None:
                report.add("organization_missing")
                report.missing_organizations.add(alias)
                report.note(account.username, f"skipped: organization {alias} not found")
                ok = False
            elif group not in org[1]:
                report.add("group_missing")
                report.missing_organizations.add(f"{alias}/{group}")
                report.note(account.username, f"skipped: organization {alias} has no group {group}")
                ok = False
            else:
                found[alias] = (org[0], org[1][group])
        return found if ok else None


def _account_mode(credentials: list[dict[str, Any]]) -> str:
    password = next((c for c in credentials if c.get("type") == "password"), None)
    return FIXED if password is not None and password.get("userLabel") == FIXED_LABEL else TEMPORARY


async def _label_fixed(kc: Any, user_id: str) -> None:
    credentials = await kc.get_user_credentials(user_id)
    password = next((c for c in credentials if c.get("type") == "password"), None)
    if password is not None and password.get("userLabel") != FIXED_LABEL:
        await kc.set_credential_label(user_id, password["id"], FIXED_LABEL)


async def _plan_authority(
    kc: Any,
    account: TestAccount,
    user_id: str | None,
    orgs: dict[str, tuple[str, str]],
    report: TestAccountsReport,
) -> list[Callable[[str], Awaitable[None]]]:
    """Exactly the declared realm role and organization groups. Ops take the user id.

    `user_id` None is an account still to be created: it holds nothing yet.
    """
    ops: list[Callable[[str], Awaitable[None]]] = []
    name = account.username

    held = await kc.get_user_realm_role_names(user_id) if user_id else set()
    for role in sorted(TEST_REALM_ROLES):
        if role in account.realm_roles and role not in held:
            report.add("realm_roles_added")
            report.note(name, f"+ realm role {role}")
            ops.append(lambda uid, role=role: kc.add_user_realm_role(uid, role))
        elif role not in account.realm_roles and role in held:
            report.add("realm_roles_removed")
            report.note(name, f"- realm role {role}")
            ops.append(lambda uid, role=role: kc.remove_user_realm_role(uid, role))

    current = await kc.get_user_organizations(user_id) if user_id else []
    current_ids = {o["id"]: o.get("alias") or o["id"] for o in current}
    declared_ids = {org_id for org_id, _ in orgs.values()}
    for org_id, alias in sorted(current_ids.items(), key=lambda kv: kv[1]):
        if org_id in declared_ids:
            continue
        member = await kc.get_organization_member(org_id, user_id)
        if member is not None and member.get("membershipType") == "MANAGED":
            report.add("managed_memberships")
            report.note(name, f"kept: managed membership of {alias} (removing it deletes the account)")
            continue
        report.add("organizations_left")
        report.note(name, f"- organization {alias}")
        ops.append(lambda uid, org_id=org_id: kc.remove_user_from_organization(org_id, uid))

    for alias, (org_id, group_id) in sorted(orgs.items()):
        group_name = dict(account.organizations)[alias]
        if org_id not in current_ids:
            report.add("organizations_joined")
            report.add("groups_added")
            report.note(name, f"+ {alias}/{group_name}")

            async def join(uid: str, org_id: str = org_id, group_id: str = group_id) -> None:
                await kc.ensure_user_in_organization(org_id, uid)
                await kc.ensure_user_in_org_group(org_id, group_id, uid)

            ops.append(join)
            continue
        in_groups = await kc.get_member_org_groups(org_id, user_id)
        for g in in_groups:
            if g.get("id") != group_id:
                report.add("groups_removed")
                report.note(name, f"- {alias}/{g.get('name') or g.get('id')}")
                ops.append(lambda uid, org_id=org_id, gid=g["id"]: kc.remove_user_from_org_group(org_id, gid, uid))
        if not any(g.get("id") == group_id for g in in_groups):
            report.add("groups_added")
            report.note(name, f"+ {alias}/{group_name}")
            ops.append(
                lambda uid, org_id=org_id, group_id=group_id: kc.ensure_user_in_org_group(org_id, group_id, uid)
            )
    return ops


async def sync_test_accounts(
    kc: Any,
    accounts: list[TestAccount],
    *,
    password_for: PasswordFor,
    dry_run: bool = False,
    rotate: bool = False,
) -> TestAccountsReport:
    """Converge the realm's test accounts on `accounts`. Idempotent without `rotate`.

    Everything is read and decided first; a run that needs a password and has no template
    raises `TestAccountsRefused` before any write. `kc` is an authenticated
    `KeycloakAdminClient` (or anything answering the same calls).
    """
    report = TestAccountsReport()
    report.add("declared", len(accounts))
    group_id, managed = await _marker_group(kc)
    for role in sorted({r for a in accounts for r in a.realm_roles}):
        if await kc.get_realm_role(role) is None:
            raise TestAccountsRefused(
                f"realm role {role} does not exist; run `celine-policies keycloak bootstrap` first"
            )
    organizations = _Organizations(kc)

    ops: list[_Op] = []
    needs_password: list[str] = []
    creating = False
    declared = {a.username for a in accounts}

    for account in accounts:
        name = account.username
        existing = managed.get(name)
        if existing is None and await kc.get_user_by_username(name) is not None:
            report.add("unmanaged_collisions")
            report.note(name, "skipped: an account outside /test-accounts holds the username")
            continue
        orgs = await organizations.resolve(account, report)
        if orgs is None:
            continue

        if existing is None:
            report.add("created")
            report.note(name, f"created ({account.password} password)")
            needs_password.append(name)
            creating = True
            authority = await _plan_authority(kc, account, None, orgs, report)
            ops.append(_create_op(kc, account, authority, password_for, report))
            continue

        user_id = existing["id"]
        before = len(report.changes)
        full = await kc.get_user_by_id(user_id) or existing
        if bool(full.get("enabled")) != account.enabled:
            report.add("enabled" if account.enabled else "disabled")
            report.note(name, "enabled" if account.enabled else "disabled")
            ops.append(lambda uid=user_id, on=account.enabled: kc.set_user_enabled(uid, on))
        if any(full.get(k) != v for k, v in account.profile.items()):
            report.add("profile_written")
            report.note(name, "placeholder profile put back")
            p = account.profile
            ops.append(
                lambda uid=user_id, p=p: kc.update_user_profile(
                    uid,
                    first_name=p["firstName"],
                    last_name=p["lastName"],
                    email=p["email"],
                    email_verified=p["emailVerified"],
                )
            )
        for op in await _plan_authority(kc, account, user_id, orgs, report):
            ops.append(lambda op=op, uid=user_id: op(uid))

        if account.enabled:
            mode = _account_mode(await kc.get_user_credentials(user_id))
            if rotate and account.password == FIXED:
                report.add("passwords_rotated")
                report.note(name, "fixed password rotated")
                needs_password.append(name)
                ops.append(_rotate_op(kc, account, user_id, password_for, report))
            elif mode != account.password:
                report.add("mode_drift")
                actual = "marked fixed" if mode == FIXED else "not marked fixed (temporary, or reset outside this command)"
                report.note(name, f"password is {actual}, declared {account.password}; not applied")
        if len(report.changes) == before:
            report.add("unchanged")

    # Disable, never delete: a test account the file no longer names.
    for username, account in sorted(managed.items()):
        if username not in declared and account.get("enabled"):
            report.add("disabled")
            report.note(username, "disabled (no longer declared)")
            ops.append(lambda uid=account["id"]: kc.set_user_enabled(uid, False))

    if (rotate or needs_password) and any(password_for(n) is None for n in needs_password or ["test"]):
        raise TestAccountsRefused(
            "CELINE_KEYCLOAK_TEST_ACCOUNT_PASSWORD_TEMPLATE is not set; creating a test "
            "account or --rotate needs it. Nothing was written."
        )

    if dry_run:
        return report
    if creating and group_id is None:
        await kc.create_group_with_attributes(
            TEST_ACCOUNTS_GROUP.lstrip("/"), {TEST_ACCOUNTS_MARKER: [TEST_ACCOUNTS_MARKER_VALUE]}
        )
        report.group_created = True
    for op in ops:
        await op()
    return report


def _create_op(
    kc: Any,
    account: TestAccount,
    authority: list[Callable[[str], Awaitable[None]]],
    password_for: PasswordFor,
    report: TestAccountsReport,
) -> _Op:
    async def create() -> None:
        p = account.profile
        try:
            await kc.create_user(
                account.username,
                email=p["email"],
                first_name=p["firstName"],
                last_name=p["lastName"],
                email_verified=True,
                enabled=account.enabled,
                temporary_password=password_for(account.username),
                temporary=account.password == TEMPORARY,
                groups=[TEST_ACCOUNTS_GROUP],
            )
        except KeycloakError as e:
            if not _password_refused(e):
                raise
            report.add("created", -1)
            report.changes.remove((account.username, f"created ({account.password} password)"))
            report.add("password_refused")
            report.note(account.username, "not created: Keycloak refused the password (its policy)")
            return
        user = await kc.get_user_by_username(account.username)
        if user is None:
            raise KeycloakError(f"created {account.username} but could not read it back")
        if account.password == FIXED:
            await _label_fixed(kc, user["id"])
        for op in authority:
            await op(user["id"])

    return create


def _rotate_op(
    kc: Any, account: TestAccount, user_id: str, password_for: PasswordFor, report: TestAccountsReport
) -> _Op:
    async def rotate() -> None:
        try:
            await kc.set_user_password(user_id, password_for(account.username), temporary=False)
        except KeycloakError as e:
            if not _password_refused(e):
                raise
            report.add("passwords_rotated", -1)
            report.changes.remove((account.username, "fixed password rotated"))
            report.add("password_refused")
            report.note(account.username, "not rotated: Keycloak refused the password (its policy)")
            return
        await _label_fixed(kc, user_id)

    return rotate


__all__ = [
    "ALLOWED_ENVS",
    "COUNTS",
    "FIXED",
    "FIXED_LABEL",
    "TEMPORARY",
    "TEST_ACCOUNTS_GROUP",
    "TEST_ACCOUNTS_MARKER",
    "TEST_ACCOUNTS_MARKER_VALUE",
    "TEST_EMAIL_DOMAIN",
    "TEST_LAST_NAME",
    "TestAccount",
    "TestAccountsRefused",
    "TestAccountsReport",
    "load_test_accounts",
    "parse_test_accounts",
    "refusal",
    "sync_test_accounts",
]
