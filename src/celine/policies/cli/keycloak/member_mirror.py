"""Mirrors of a source realm's members in an intermediate realm (REQ-0021, ADR-0015).

An intermediate deployment (staging, preprod) holds no person: it holds **mirrors** of
prod's members, so that settlement, points and the webapp line up with prod's outputs
without a translation. A mirror is an account whose

- **id** is the member's account subject in the source realm (prod's Keycloak `sub`),
- **username** is the member's key in the source registry,
- **enabled** flag is the member's status (`active` or not),

and that carries no personal e-mail or name, no credential and no attribute. Nobody signs
in as a mirror: the team enters one by impersonation.

## The placeholder profile

The realm's user profile requires an e-mail, a first and a last name. A mirror without
them stops every impersonation at Keycloak's "Update Account Information" form
(`VERIFY_PROFILE`, staging, 2026-11-02). So a mirror carries placeholders made from its
own key, nothing of the person: first name = the key, last name = `mirror`, e-mail =
`<key>@mirror.invalid`, verified (`.invalid` is reserved and never delivers, RFC 2606;
verified so that no `VERIFY_EMAIL` follows). A key unfit for an address or a name uses the
subject instead: one import carries every new mirror, and a value the realm refuses would
fail them all. A mirror made before the placeholders, or edited by hand, is put back to them.

## Why a partial import

`POST /users` assigns its own id. `POST /partialImport` keeps the `id` it is given
(measured on 26.7.3, 2026-10-30), and with `ifResourceExists: FAIL` it can never
overwrite an account: the mirror checks first and imports only accounts nobody holds.

## How a mirror is told from everyone else

By membership of the realm group `/member-mirrors`, which the import puts it in. Not by a
user attribute: Keycloak drops an attribute the realm's user profile does not declare, and
no realm here declares one. The group carries the source issuer as its `celine_mirror`
attribute (group attributes are kept), and a group of that name that does not carry this
source is refused rather than adopted. The group grants nothing: realm groups carry no
authority (ADR-0012), and no token carries a `groups` claim.

## What is never done

- An account outside the group is never written, whatever it collides with.
- A mirror is never deleted: one whose member left the source or went inactive is
  disabled. Organization memberships are added, never removed.
- No member's key, subject or anything else of a member is printed: the report is counts.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from celine.provisioning.provisioner import MEMBER_GROUP

logger = logging.getLogger(__name__)

#: The realm group every mirror is in, and only mirrors. Not a role-hierarchy name.
MIRROR_GROUP = "/member-mirrors"
#: The group attribute naming the source realm (its issuer URL).
MIRROR_MARKER = "celine_mirror"
#: The source registry route (rec-registry, action `mirror`, scope `rec-registry.mirror`).
MIRROR_EXPORT_PATH = "/admin/export/mirror"

#: The fine-grained admin policy naming the accounts that may impersonate mirrors, and the
#: permission binding it to the mirror group. A prefix of their own: `keycloak sync` reads
#: and prunes only names starting with `celine-policies:`.
IMPERSONATORS_POLICY = "celine-member-mirror:impersonators"
IMPERSONATION_PERMISSION = "celine-member-mirror:impersonate"
#: `view` finds the group, `view-members` lists the mirrors, `impersonate-members` enters
#: one. Nothing that writes.
IMPERSONATION_SCOPES = ("impersonate-members", "view", "view-members")
#: The realm-management roles an impersonator also needs: the admin console refuses an
#: account holding none, whatever its fine-grained permissions (staging, 2026-11-02).
#: `query-users` and `query-groups` open it and let the searches run; what they return is
#: still filtered by the permissions above. **Checked, never granted:** admin roles for
#: people are not a scheduled job's to give, and Keycloak refused this client's grant
#: (403, staging, 2026-11-02) although it holds both. A master admin assigns them once;
#: an impersonator without them is counted and the run exits 2.
IMPERSONATOR_CONSOLE_ROLES = ("query-users", "query-groups")

#: The placeholder profile (see "The placeholder profile" above).
MIRROR_LAST_NAME = "mirror"
MIRROR_EMAIL_DOMAIN = "mirror.invalid"
#: A key used as is in the placeholders: what both an e-mail local part and Keycloak's
#: person-name validator accept. Anything else falls back to the subject.
_PLACEHOLDER_SAFE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")

#: Values of ENV the command refuses: the source itself.
REFUSED_ENVS = frozenset({"prod", "production"})

ACTIVE = "active"

#: The counts a run reports, in print order.
COUNTS = (
    "members",
    "without_subject",
    "invalid_subject",
    "export_conflicts",
    "created",
    "enabled",
    "disabled",
    "memberships_added",
    "profile_written",
    "unchanged",
    "unmanaged_collisions",
    "username_taken",
    "key_changed",
    "organization_missing",
    "impersonators_missing",
    "impersonators_refused",
    "impersonation_written",
    "impersonators_without_console_roles",
)
#: The counts that mean a member could not be mirrored as the source has it.
ATTENTION = frozenset(
    {
        "invalid_subject",
        "export_conflicts",
        "unmanaged_collisions",
        "username_taken",
        "key_changed",
        "organization_missing",
        "impersonators_missing",
        "impersonators_refused",
        "impersonators_without_console_roles",
    }
)


class MirrorSourceError(RuntimeError):
    """The export could not be read, or is not the shape the mirror reads."""


class MirrorRefused(RuntimeError):
    """The target realm is not one this mirror may write."""


@dataclass(frozen=True)
class MirrorMember:
    """One member row of the export, reduced to what the Keycloak half reads."""

    community: str
    key: str
    subject: str | None
    active: bool
    invalid_subject: bool = False


@dataclass
class MirrorReport:
    """What a run did (or, dry, would do): counts only."""

    counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(COUNTS, 0))
    missing_organizations: set[str] = field(default_factory=set)
    group_created: bool = False

    def add(self, name: str, n: int = 1) -> None:
        self.counts[name] += n

    @property
    def needs_attention(self) -> bool:
        """Whether a member could not be mirrored: the run exits 2."""
        return any(self.counts[name] for name in ATTENTION)


# ---------------------------------------------------------------------------
# Where it may run
# ---------------------------------------------------------------------------


def _host(url: str) -> str:
    return (urlsplit(url.strip()).hostname or "").lower()


def refusal(*, env: str, target_base_url: str, source_issuer: str) -> str | None:
    """Why this run must not write the target, or None.

    Checked before the source is read or Keycloak is asked anything. `ENV` unset is
    `prod` (`KeycloakSettings.env`), so a run that names no environment is refused too.
    """
    if env.strip().lower() in REFUSED_ENVS:
        return (
            f"mirror-members writes an intermediate realm and never prod; ENV is "
            f"'{env.strip()}'. Set ENV to the intermediate environment (e.g. staging)."
        )
    target, source = _host(target_base_url), _host(source_issuer)
    if not source:
        return "the source issuer is not a URL"
    if target == source:
        return (
            f"the target Keycloak ({target}) is the source's own; a mirror writes "
            f"another realm"
        )
    return None


# ---------------------------------------------------------------------------
# Reading the export
# ---------------------------------------------------------------------------


def parse_mirror_export(data: Any) -> list[MirrorMember]:
    """Check the export's shape and reduce it to `MirrorMember`s.

    A malformed document is refused whole: a mirror that reads half an export would
    disable every member of the half it missed. A subject that is not a UUID is kept as
    an `invalid_subject` row, counted and skipped. A UUID is compared lower-case, the
    form the registry stores and Keycloak emits.
    """
    if not isinstance(data, dict) or not isinstance(data.get("communities"), list):
        raise MirrorSourceError("the export has no `communities` list")
    members: list[MirrorMember] = []
    for i, community in enumerate(data["communities"]):
        if not isinstance(community, dict):
            raise MirrorSourceError(f"communities[{i}] is not an object")
        key = community.get("community")
        rows = community.get("members")
        if not isinstance(key, str) or not key or not isinstance(rows, list):
            raise MirrorSourceError(f"communities[{i}] needs `community` and `members`")
        for j, row in enumerate(rows):
            if not isinstance(row, dict) or not isinstance(row.get("key"), str) or not row["key"].strip():
                raise MirrorSourceError(f"communities[{i}].members[{j}] has no key")
            raw = row.get("subject")
            subject, invalid = None, False
            if raw is not None:
                try:
                    subject = str(uuid.UUID(str(raw))).lower()
                except ValueError:
                    invalid = True
            members.append(
                MirrorMember(
                    community=key,
                    key=row["key"].strip(),
                    subject=subject,
                    active=row.get("status") == ACTIVE,
                    invalid_subject=invalid,
                )
            )
    return members


def read_mirror_file(path: Path) -> Any:
    """The export saved as a JSON file, for tests and offline runs."""
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise MirrorSourceError(f"{path}: {e}") from e


def _token_provider(**kwargs: Any) -> Any:
    """The SDK's client-credentials provider. Imported late: it pulls an HTTP stack
    every other `keycloak` command would pay for."""
    from celine.sdk.auth import OidcClientCredentialsProvider

    return OidcClientCredentialsProvider(**kwargs)


async def fetch_mirror_export(
    *,
    source_url: str,
    issuer: str,
    client_id: str,
    client_secret: str,
    timeout: float = 30.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Any:
    """`GET <source_url>/admin/export/mirror` with a client-credentials token of the
    source realm. The one source route this command calls."""
    url = f"{source_url.rstrip('/')}{MIRROR_EXPORT_PATH}"
    provider = _token_provider(
        base_url=issuer, client_id=client_id, client_secret=client_secret, timeout=timeout
    )
    try:
        token = await provider.get_token()
    except Exception as e:
        raise MirrorSourceError(
            f"could not get a token from {issuer} as '{client_id}': {type(e).__name__}"
        ) from e
    async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
        try:
            response = await client.get(
                url, headers={"Authorization": f"Bearer {token.access_token}"}
            )
        except httpx.HTTPError as e:
            raise MirrorSourceError(f"{url} unreachable: {type(e).__name__}") from e
    if response.status_code != 200:
        raise MirrorSourceError(
            f"{url} answered {response.status_code} to '{client_id}' (token issuer "
            f"{issuer}). A 401 is usually an audience or issuer the gateway does not "
            f"accept; a 403 means '{client_id}' does not hold rec-registry.mirror."
        )
    try:
        return response.json()
    except ValueError as e:
        raise MirrorSourceError(f"{url} returned something that is not JSON") from e


# ---------------------------------------------------------------------------
# Writing the target
# ---------------------------------------------------------------------------


@dataclass
class _Wanted:
    username: str
    active: bool
    communities: set[str]


def placeholder_profile(username: str, subject: str) -> dict[str, Any]:
    """The non-personal profile a mirror carries: from its key, or its subject when the
    key is unfit for an address or a name."""
    base = username if _PLACEHOLDER_SAFE.match(username) and ".." not in username else subject
    return {
        "firstName": base,
        "lastName": MIRROR_LAST_NAME,
        "email": f"{base}@{MIRROR_EMAIL_DOMAIN}",
        "emailVerified": True,
    }


def _wanted(members: list[MirrorMember], report: MirrorReport) -> tuple[dict[str, _Wanted], set[str]]:
    """One wanted mirror per subject, and the subjects the export contradicts itself on.

    A subject under two keys, or a key under two subjects, cannot be one account: those
    are skipped and left as they are.
    """
    rows: dict[str, list[MirrorMember]] = defaultdict(list)
    for m in members:
        if m.invalid_subject:
            report.add("invalid_subject")
        elif m.subject is None:
            report.add("without_subject")
        else:
            rows[m.subject].append(m)

    conflicted: set[str] = set()
    by_username: dict[str, set[str]] = defaultdict(set)
    for subject, ms in rows.items():
        keys = {m.key.lower() for m in ms}
        if len(keys) > 1:
            conflicted.add(subject)
        for k in keys:
            by_username[k].add(subject)
    for subjects in by_username.values():
        if len(subjects) > 1:
            conflicted |= subjects
    report.add("export_conflicts", len(conflicted))

    wanted = {
        subject: _Wanted(
            username=ms[0].key.lower(),
            active=any(m.active for m in ms),
            communities={m.community for m in ms},
        )
        for subject, ms in rows.items()
        if subject not in conflicted
    }
    return wanted, conflicted


async def _mirror_group(kc: Any, source: str) -> tuple[str | None, dict[str, dict[str, Any]]]:
    """The mirror group's id and its members by id; refuses a group this source did not make."""
    group = await kc.get_group_by_path(MIRROR_GROUP)
    if group is None:
        return None, {}
    full = await kc.get_group(group["id"])
    if (full.get("attributes") or {}).get(MIRROR_MARKER) != [source]:
        raise MirrorRefused(
            f"the realm has a group {MIRROR_GROUP} that does not carry "
            f"{MIRROR_MARKER}={source}; it was not made by a mirror of this source, "
            f"and its members are not taken over"
        )
    members = await kc.get_group_members(group["id"])
    return group["id"], {u["id"]: u for u in members}


class _Organizations:
    """Community key -> (organization id, its `viewers` group id), or None, read once."""

    def __init__(self, kc: Any, report: MirrorReport):
        self._kc, self._report = kc, report
        self._cache: dict[str, tuple[str, str] | None] = {}

    async def get(self, alias: str) -> tuple[str, str] | None:
        if alias not in self._cache:
            org = await self._kc.get_organization_by_alias(alias)
            group = await self._kc.get_org_group_by_name(org["id"], MEMBER_GROUP) if org else None
            self._cache[alias] = (org["id"], group["id"]) if org and group else None
        return self._cache[alias]

    async def resolve(self, communities: set[str]) -> list[tuple[str, str]] | None:
        """Every community's organization, or None (and counted) when one is missing."""
        found = []
        missing = set()
        for alias in sorted(communities):
            org = await self.get(alias)
            if org is None:
                missing.add(alias)
            else:
                found.append(org)
        if missing:
            self._report.add("organization_missing")
            self._report.missing_organizations |= missing
            return None
        return found


async def _join(kc: Any, orgs: list[tuple[str, str]], user_id: str, dry_run: bool) -> int:
    """Add a mirror to each organization and its `viewers` group it lacks; how many it lacked."""
    added = 0
    for org_id, viewers_id in orgs:
        missing = False
        if not await kc.is_user_in_organization(org_id, user_id):
            missing = True
            if not dry_run:
                await kc.add_user_to_organization(org_id, user_id)
        if not await kc.is_user_in_org_group(org_id, viewers_id, user_id):
            missing = True
            if not dry_run:
                await kc.ensure_user_in_org_group(org_id, viewers_id, user_id)
        added += missing
    return added


async def mirror_members(
    kc: Any,
    members: list[MirrorMember],
    *,
    source: str,
    dry_run: bool,
    impersonators: list[str] | None = None,
) -> MirrorReport:
    """Converge the target realm's mirrors on `members`. Idempotent.

    `kc` is an authenticated `KeycloakAdminClient` (or anything answering the same
    calls). `source` is the source realm's issuer URL, stored on the mirror group.
    `impersonators` names target accounts that may impersonate the mirrors; None or
    empty leaves the permission as it is.
    """
    report = MirrorReport()
    report.add("members", len(members))
    wanted, conflicted = _wanted(members, report)

    group_id, managed = await _mirror_group(kc, source)
    orgs = _Organizations(kc, report)

    to_create: list[dict[str, Any]] = []
    joins: list[tuple[str, list[tuple[str, str]]]] = []
    for subject, w in sorted(wanted.items()):
        account = managed.get(subject)
        if account is not None:
            if (account.get("username") or "").lower() != w.username:
                report.add("key_changed")
                continue
            resolved = await orgs.resolve(w.communities)
            changed = False
            if bool(account.get("enabled")) != w.active:
                changed = True
                report.add("enabled" if w.active else "disabled")
                if not dry_run:
                    await kc.set_user_enabled(subject, w.active)
            profile = placeholder_profile(w.username, subject)
            if any(account.get(k) != v for k, v in profile.items()):
                changed = True
                report.add("profile_written")
                if not dry_run:
                    await kc.update_user_profile(
                        subject,
                        first_name=profile["firstName"],
                        last_name=profile["lastName"],
                        email=profile["email"],
                        email_verified=profile["emailVerified"],
                    )
            if resolved is not None:
                added = await _join(kc, resolved, subject, dry_run)
                report.add("memberships_added", added)
                changed = changed or bool(added)
            if not changed and resolved is not None:
                report.add("unchanged")
            continue

        if await kc.get_user_by_id(subject) is not None:
            report.add("unmanaged_collisions")
            continue
        holder = await kc.get_user_by_username(w.username)
        if holder is not None:
            report.add("username_taken" if holder["id"] in managed else "unmanaged_collisions")
            continue
        resolved = await orgs.resolve(w.communities)
        if resolved is None:
            continue
        to_create.append(
            {
                "id": subject,
                "username": w.username,
                "enabled": w.active,
                "groups": [MIRROR_GROUP],
                **placeholder_profile(w.username, subject),
            }
        )
        joins.append((subject, resolved))

    # Disable, never delete: a mirror the source no longer has as an active member.
    for subject, account in sorted(managed.items()):
        if subject in wanted or subject in conflicted:
            continue
        if account.get("enabled"):
            report.add("disabled")
            if not dry_run:
                await kc.set_user_enabled(subject, False)

    if to_create and group_id is None and not dry_run:
        group_id = await kc.create_group_with_attributes(
            MIRROR_GROUP.lstrip("/"), {MIRROR_MARKER: [source]}
        )
        report.group_created = True
    if to_create:
        report.add("created", len(to_create))
        if not dry_run:
            await kc.partial_import({"ifResourceExists": "FAIL", "users": to_create})
    for subject, resolved in joins:
        report.add("memberships_added", len(resolved))
        if not dry_run:
            await _join(kc, resolved, subject, dry_run=False)

    if impersonators:
        if group_id is None and not dry_run:
            group_id = await kc.create_group_with_attributes(
                MIRROR_GROUP.lstrip("/"), {MIRROR_MARKER: [source]}
            )
            report.group_created = True
        await _grant_impersonation(kc, group_id, set(managed) | set(wanted), impersonators, dry_run, report)
    return report


async def _grant_impersonation(
    kc: Any,
    group_id: str | None,
    mirror_ids: set[str],
    impersonators: list[str],
    dry_run: bool,
    report: MirrorReport,
) -> None:
    """Let exactly the named accounts impersonate members of the mirror group, nothing else.

    A user policy naming them, and a `Groups` permission on the mirror group with
    `IMPERSONATION_SCOPES`, bound to that policy. A name that is not an account is
    reported; a mirror is never made an impersonator.
    """
    ap_uuid = await kc.get_admin_permissions_client_uuid()
    if ap_uuid is None:
        raise MirrorRefused(
            "fine-grained admin permissions are off in the target realm; run "
            "`celine-policies keycloak bootstrap` first (platform.yaml turns them on)"
        )

    ids: set[str] = set()
    for name in sorted(set(impersonators)):
        account = await kc.get_user_by_username(name)
        if account is None:
            report.add("impersonators_missing")
        elif account["id"] in mirror_ids:
            report.add("impersonators_refused")
        else:
            ids.add(account["id"])
    if not ids:
        return

    await _check_console_roles(kc, ids, report)

    policy = await kc.find_admin_policy_by_name(ap_uuid, IMPERSONATORS_POLICY)
    policy_id = policy["id"] if policy else None
    if policy is None or kc.admin_policy_user_ids(policy) != ids:
        report.add("impersonation_written")
        if not dry_run:
            if policy is None:
                policy_id = await kc.create_admin_user_policy(ap_uuid, IMPERSONATORS_POLICY, sorted(ids))
            else:
                await kc.update_admin_user_policy(ap_uuid, policy["id"], IMPERSONATORS_POLICY, sorted(ids))

    permission = await kc.find_admin_policy_by_name(ap_uuid, IMPERSONATION_PERMISSION)
    if permission is not None and policy_id is not None:
        scopes = {s.get("name") for s in await kc.get_admin_permission_scopes(ap_uuid, permission["id"])}
        resources = [r.get("name") for r in await kc.get_admin_permission_resources(ap_uuid, permission["id"])]
        policies = [p.get("id") for p in await kc.get_admin_permission_policies(ap_uuid, permission["id"])]
        if scopes == set(IMPERSONATION_SCOPES) and resources == [group_id] and policies == [policy_id]:
            return
    report.add("impersonation_written")
    if dry_run or group_id is None or policy_id is None:
        return
    await kc.put_group_scope_permission(
        ap_uuid,
        permission["id"] if permission else None,
        name=IMPERSONATION_PERMISSION,
        description=f"Managed by celine-policies mirror-members: named accounts impersonate {MIRROR_GROUP}",
        group_id=group_id,
        scopes=list(IMPERSONATION_SCOPES),
        policy_id=policy_id,
    )


async def _check_console_roles(kc: Any, user_ids: set[str], report: MirrorReport) -> None:
    """Count the impersonators missing any of `IMPERSONATOR_CONSOLE_ROLES`. Writes nothing."""
    rm_client = await kc.get_realm_management_client()
    if not rm_client:
        raise MirrorRefused("the target realm has no realm-management client")
    for user_id in sorted(user_ids):
        held = {r["name"] for r in await kc.get_user_client_roles(user_id, rm_client["id"])}
        if not set(IMPERSONATOR_CONSOLE_ROLES) <= held:
            report.add("impersonators_without_console_roles")


__all__ = [
    "IMPERSONATION_PERMISSION",
    "IMPERSONATION_SCOPES",
    "IMPERSONATORS_POLICY",
    "IMPERSONATOR_CONSOLE_ROLES",
    "MIRROR_EMAIL_DOMAIN",
    "MIRROR_GROUP",
    "MIRROR_LAST_NAME",
    "MIRROR_MARKER",
    "MirrorMember",
    "MirrorRefused",
    "MirrorReport",
    "MirrorSourceError",
    "fetch_mirror_export",
    "mirror_members",
    "parse_mirror_export",
    "placeholder_profile",
    "read_mirror_file",
    "refusal",
]
