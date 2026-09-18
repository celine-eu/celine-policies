"""The platform level of a realm: what `keycloak bootstrap` owns, and how it converges it.

Three commands used to write realm-wide state as a side effect of their own work —
`sync-orgs` and `sync-users` turned on Organizations and created the role groups,
`sync` turned on fine-grained admin permissions — and nothing at all wrote the
sign-in settings, which reached a realm only through an import that Keycloak skips
for a realm that already exists. `platform.yaml` is the one declaration of that
level, and `bootstrap` its one writer. The other commands check it and refuse.

## Only what is declared

`bootstrap` diffs the keys `platform.yaml` names against the realm and `PUT`s only the
ones that differ, as a partial representation. A key the file does not name is
never sent, so it is never reset to a default. Measured on 26.7.3: a realm `PUT`
carrying some keys changes exactly those keys. That is also what keeps
`smtpServer.password`, which Keycloak returns masked, out of every settings write.

## What the file cannot say

Refused before anything is read from Keycloak, each for a reason:

- `smtpServer` — a credential. It comes from the environment (`CELINE_KEYCLOAK_SMTP_*`).
- `bruteForceProtected` — on or off per environment (`CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED`).
- `verifyEmail` — would stop every existing account with `emailVerified: false`.
- `passwordPolicy` — Keycloak's default, by decision.

And a deployment overlay may change `supportedLocales` and nothing else.

## What the environment can say

A deployment differs from the image in ways a baked file cannot know: a stock Keycloak
ships no `rec` theme (spindoxlabs/ds#36). Each key in `ENV_OVERRIDABLE_SETTINGS` takes
`CELINE_KEYCLOAK_PLATFORM_<KEY>`, applied after the overlays and checked like the file.
The value `null` drops the key from the declaration: `bootstrap` then leaves the realm's
value alone, which on a new realm is Keycloak's default.

## One built-in client: `account-console`

A realm Keycloak creates itself gives its account console the default client scopes
`web-origins acr profile roles basic email`. A realm imported from a file that declares its
own client scopes gives it none, and the console's token then carries no
`resource_access.account`: the Account API answers `403` and the console shows "Something
went wrong" (measured on 26.7.3, plan participants-may-choose-a-passkey-or-a-one-time-code).
The import cannot say otherwise without declaring the `account` client and its roles as
well. So `bootstrap` adds the missing ones, to that client only, and never removes one.
It is the one client this level touches: every other client is `sync`'s.

## Nested objects are replaced whole

Keycloak does not merge a nested object on `PUT`: `smtpServer` with one field is a
`400`, and `attributes` with one entry silently drops Keycloak's own entries. No key
this module accepts is nested, and that is a constraint on adding one, not an accident.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from celine.policies.cli.keycloak.client import KeycloakError

if TYPE_CHECKING:
    from celine.policies.cli.keycloak.client import KeycloakAdminClient
    from celine.policies.cli.keycloak.settings import RealmAdminSettings, SmtpSettings

logger = logging.getLogger(__name__)

#: Where `bootstrap` looks when no path is given: `/app/platform.yaml` in the image,
#: from its working directory, as `sync` finds `clients.yaml`.
DEFAULT_PLATFORM_FILE = Path("platform.yaml")

_BOOL = "boolean"
_SECONDS = "non-negative integer"
_TEXT = "string"
_LOCALES = "list of locale codes"

#: Every realm key `platform.yaml` may declare, and the type it must have. Adding a
#: key here is what lets `bootstrap` own it.
REALM_SETTING_TYPES: dict[str, str] = {
    "organizationsEnabled": _BOOL,
    "adminPermissionsEnabled": _BOOL,
    "editUsernameAllowed": _BOOL,
    "registrationAllowed": _BOOL,
    "resetPasswordAllowed": _BOOL,
    "loginWithEmailAllowed": _BOOL,
    "duplicateEmailsAllowed": _BOOL,
    "internationalizationEnabled": _BOOL,
    "supportedLocales": _LOCALES,
    "defaultLocale": _TEXT,
    "loginTheme": _TEXT,
    "emailTheme": _TEXT,
    "accessTokenLifespan": _SECONDS,
    "accessTokenLifespanForImplicitFlow": _SECONDS,
    "ssoSessionIdleTimeout": _SECONDS,
    "ssoSessionMaxLifespan": _SECONDS,
    "actionTokenGeneratedByAdminLifespan": _SECONDS,
    "actionTokenGeneratedByUserLifespan": _SECONDS,
    "permanentLockout": _BOOL,
    "waitIncrementSeconds": _SECONDS,
    "quickLoginCheckMilliSeconds": _SECONDS,
    "minimumQuickLoginWaitSeconds": _SECONDS,
    "maxFailureWaitSeconds": _SECONDS,
    "failureFactor": _SECONDS,
}

#: Realm keys a declaration may not name, with the reason given when one does.
REFUSED_REALM_SETTINGS: dict[str, str] = {
    "smtpServer": "it carries a credential; bootstrap applies it from the "
    "CELINE_KEYCLOAK_SMTP_* environment variables",
    "bruteForceProtected": "it is set per environment by CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED",
    "verifyEmail": "it would stop every existing account with emailVerified: false at "
    "its next sign-in; the invitation already verifies the address",
    "passwordPolicy": "the realm keeps Keycloak's default policy",
}

#: The only keys a deployment overlay may change.
OVERLAY_REALM_SETTINGS = frozenset({"supportedLocales"})

#: Prefix of the variables that override a declared value; the realm key follows in upper
#: snake case (`loginTheme` -> `CELINE_KEYCLOAK_PLATFORM_LOGIN_THEME`). `PLATFORM_` keeps
#: them apart from the connection settings under `CELINE_KEYCLOAK_`.
ENV_OVERRIDE_PREFIX = "CELINE_KEYCLOAK_PLATFORM_"

#: Written as a variable's value, the key is not declared at all: `bootstrap` stops
#: managing it, exactly as if `platform.yaml` did not name it. Nothing is reset.
ENV_OVERRIDE_NULL = "null"

#: The keys a deployment may override from the environment. What a deployment reasonably
#: differs on: the themes its Keycloak ships, languages, lifespans, brute-force tuning.
#: Left out on purpose: the features other commands require (`organizationsEnabled`,
#: `adminPermissionsEnabled`), `internationalizationEnabled` (provisioning's `locale` is
#: dropped without it), and the username and email rules the invitation relies on.
ENV_OVERRIDABLE_SETTINGS = (
    "loginTheme",
    "emailTheme",
    "supportedLocales",
    "defaultLocale",
    "registrationAllowed",
    "resetPasswordAllowed",
    "accessTokenLifespan",
    "accessTokenLifespanForImplicitFlow",
    "ssoSessionIdleTimeout",
    "ssoSessionMaxLifespan",
    "actionTokenGeneratedByAdminLifespan",
    "actionTokenGeneratedByUserLifespan",
    "permanentLockout",
    "waitIncrementSeconds",
    "quickLoginCheckMilliSeconds",
    "minimumQuickLoginWaitSeconds",
    "maxFailureWaitSeconds",
    "failureFactor",
)

#: Locales the `rec` login and email themes ship bundles for, and the only values the
#: provisioning service accepts as a user's `locale`. A fourth is a theme and service
#: release, never an overlay.
THEME_LOCALES = frozenset({"it", "en", "es"})

#: Realm keys whose value names a theme of the given type in `serverinfo.themes`.
THEME_SETTINGS = {"loginTheme": "login", "emailTheme": "email"}

_TOP_LEVEL_KEYS = frozenset({"realm_settings", "role_groups"})


def env_override_name(key: str) -> str:
    """The variable that overrides realm key `key`."""
    return ENV_OVERRIDE_PREFIX + re.sub(r"(?<!^)(?=[A-Z])", "_", key).upper()


class PlatformDeclarationError(ValueError):
    """A platform declaration or overlay that `bootstrap` refuses to apply."""


class PlatformNotReady(KeycloakError):
    """A command found the platform level missing a feature it depends on.

    Raised instead of turning the feature on: a command writes only its own level,
    and `bootstrap` is the one writer of this one.
    """


@dataclass(frozen=True)
class RoleGroup:
    """A realm-wide group and the realm role every member of it holds."""

    path: str
    realm_role: str


@dataclass
class PlatformDeclaration:
    """`platform.yaml` with its overlays applied, and where each value came from."""

    realm_settings: dict[str, Any] = field(default_factory=dict)
    role_groups: list[RoleGroup] = field(default_factory=list)
    #: realm key -> the file that set it last
    sources: dict[str, str] = field(default_factory=dict)
    platform_file: str = ""


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _read_mapping(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise PlatformDeclarationError(f"{path}: file not found")
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise PlatformDeclarationError(f"{path}: not valid YAML: {e}") from e
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise PlatformDeclarationError(f"{path}: expected a mapping at the top level")
    unknown = sorted(set(data) - _TOP_LEVEL_KEYS)
    if unknown:
        raise PlatformDeclarationError(
            f"{path}: unknown top-level key(s) {unknown}; "
            f"accepted: {sorted(_TOP_LEVEL_KEYS)}"
        )
    return data


def _check_value(path: "Path | str", key: str, value: Any) -> None:
    kind = REALM_SETTING_TYPES[key]
    if kind == _BOOL:
        ok = isinstance(value, bool)
    elif kind == _SECONDS:
        # bool is an int in Python, and `true` is not a lifespan.
        ok = isinstance(value, int) and not isinstance(value, bool) and value >= 0
    elif kind == _TEXT:
        ok = isinstance(value, str) and value != ""
    else:
        ok = (
            isinstance(value, list)
            and value != []
            and all(isinstance(v, str) and v for v in value)
            and len(set(value)) == len(value)
        )
    if not ok:
        raise PlatformDeclarationError(
            f"{path}: realm_settings.{key} must be a {kind}, got {value!r}"
        )


def _realm_settings(path: Path, data: dict[str, Any]) -> dict[str, Any]:
    settings = data.get("realm_settings") or {}
    if not isinstance(settings, dict):
        raise PlatformDeclarationError(f"{path}: realm_settings must be a mapping")
    for key in settings:
        if key in REFUSED_REALM_SETTINGS:
            raise PlatformDeclarationError(
                f"{path}: realm_settings.{key} is not accepted: {REFUSED_REALM_SETTINGS[key]}"
            )
        if key not in REALM_SETTING_TYPES:
            raise PlatformDeclarationError(
                f"{path}: realm_settings.{key} is not a key bootstrap owns; "
                f"accepted: {sorted(REALM_SETTING_TYPES)}"
            )
        _check_value(path, key, settings[key])
    return dict(settings)


def _role_groups(path: Path, data: dict[str, Any]) -> list[RoleGroup]:
    raw = data.get("role_groups") or []
    if not isinstance(raw, list):
        raise PlatformDeclarationError(f"{path}: role_groups must be a list")
    groups: list[RoleGroup] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict) or set(entry) != {"path", "realm_role"}:
            raise PlatformDeclarationError(
                f"{path}: role_groups[{i}] must have exactly `path` and `realm_role`"
            )
        group_path, role = entry["path"], entry["realm_role"]
        if (
            not isinstance(group_path, str)
            or not group_path.startswith("/")
            or "/" in group_path[1:]
            or len(group_path) < 2
        ):
            raise PlatformDeclarationError(
                f"{path}: role_groups[{i}].path must be a top-level group path like "
                f"/admins, got {group_path!r}"
            )
        if not isinstance(role, str) or not role:
            raise PlatformDeclarationError(
                f"{path}: role_groups[{i}].realm_role must be a role name"
            )
        groups.append(RoleGroup(path=group_path, realm_role=role))
    paths = [g.path for g in groups]
    if len(set(paths)) != len(paths):
        raise PlatformDeclarationError(f"{path}: role_groups names a group twice")
    return groups


def _check_locales(settings: dict[str, Any], sources: dict[str, str]) -> None:
    """The merged locales: only what the themes ship, and the default among them."""
    locales = settings.get("supportedLocales")
    if locales is None:
        return
    unshipped = sorted(set(locales) - THEME_LOCALES)
    if unshipped:
        raise PlatformDeclarationError(
            f"supportedLocales from {sources['supportedLocales']} names {unshipped}, "
            f"which the rec themes do not ship (they ship {sorted(THEME_LOCALES)})"
        )
    default = settings.get("defaultLocale")
    if default is not None and default not in locales:
        raise PlatformDeclarationError(
            f"supportedLocales {locales} from {sources['supportedLocales']} does not "
            f"contain defaultLocale {default!r} from {sources['defaultLocale']}"
        )


def _parse_env_value(name: str, key: str, raw: str) -> Any:
    """A variable's text as the value its key's type needs, refusing what does not parse."""
    kind = REALM_SETTING_TYPES[key]
    text = raw.strip()
    if kind == _BOOL:
        if text.lower() not in ("true", "false"):
            raise PlatformDeclarationError(f"{name}: must be true or false, got {raw!r}")
        value: Any = text.lower() == "true"
    elif kind == _SECONDS:
        if not text.isdigit():
            raise PlatformDeclarationError(f"{name}: must be a {kind}, got {raw!r}")
        value = int(text)
    elif kind == _LOCALES:
        value = [part.strip() for part in text.split(",")]
    else:
        value = text
    _check_value(name, key, value)
    return value


def apply_env_overrides(declaration: PlatformDeclaration, environ: Mapping[str, str]) -> None:
    """Override each key of `ENV_OVERRIDABLE_SETTINGS` its variable sets, in place.

    Unset or empty: the declared value stands. `null`: the key is dropped, so `bootstrap`
    leaves it alone. Anything else replaces the value and becomes the key's source.
    A locale list is comma-separated. A set variable of this prefix naming any other key
    is refused, so an override that would not apply never looks as if it did.
    """
    names = {env_override_name(key): key for key in ENV_OVERRIDABLE_SETTINGS}
    unknown = sorted(
        name for name, raw in environ.items()
        if name.startswith(ENV_OVERRIDE_PREFIX) and name not in names and raw.strip()
    )
    if unknown:
        raise PlatformDeclarationError(
            f"{unknown}: not an overridable platform setting; accepted: {sorted(names)}"
        )
    for name, key in names.items():
        raw = environ.get(name, "")
        if not raw.strip():
            continue
        if raw.strip().lower() == ENV_OVERRIDE_NULL:
            declaration.realm_settings.pop(key, None)
            declaration.sources.pop(key, None)
            continue
        declaration.realm_settings[key] = _parse_env_value(name, key, raw)
        declaration.sources[key] = name


def load_platform(
    path: Path,
    overlays: "list[Path] | tuple[Path, ...]" = (),
    environ: Mapping[str, str] | None = None,
) -> PlatformDeclaration:
    """Read `platform.yaml`, apply each overlay in order, then the environment's overrides.

    An overlay has the declaration's shape and may name `realm_settings.supportedLocales`
    only. Key-level merge, last wins, and a list replaces a list. The environment
    (`apply_env_overrides`) wins over both. Every check runs on the merged result,
    before `bootstrap` reads anything from Keycloak.
    """
    data = _read_mapping(path)
    settings = _realm_settings(path, data)
    declaration = PlatformDeclaration(
        realm_settings=settings,
        role_groups=_role_groups(path, data),
        sources={key: str(path) for key in settings},
        platform_file=str(path),
    )

    for overlay in overlays:
        odata = _read_mapping(overlay)
        if "role_groups" in odata:
            raise PlatformDeclarationError(
                f"{overlay}: an overlay may not change role_groups; "
                f"it may change only {sorted(OVERLAY_REALM_SETTINGS)}"
            )
        osettings = _realm_settings(overlay, odata)
        refused = sorted(set(osettings) - OVERLAY_REALM_SETTINGS)
        if refused:
            raise PlatformDeclarationError(
                f"{overlay}: an overlay may change only {sorted(OVERLAY_REALM_SETTINGS)}; "
                f"it names {refused}"
            )
        for key, value in osettings.items():
            declaration.realm_settings[key] = value
            declaration.sources[key] = str(overlay)

    if environ is not None:
        apply_env_overrides(declaration, environ)
    _check_locales(declaration.realm_settings, declaration.sources)
    return declaration


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SettingChange:
    key: str
    current: Any
    desired: Any
    source: str


def _same(key: str, current: Any, desired: Any) -> bool:
    # Keycloak keeps supported locales as a set; the order it returns is not ours.
    if key == "supportedLocales" and isinstance(current, list):
        return set(current) == set(desired)
    return current == desired


def plan_realm_settings(
    desired: dict[str, Any],
    current: dict[str, Any],
    sources: dict[str, str],
) -> list[SettingChange]:
    """The declared keys whose realm value differs, in declaration order."""
    return [
        SettingChange(key, current.get(key), value, sources.get(key, ""))
        for key, value in desired.items()
        if not _same(key, current.get(key), value)
    ]


def check_themes(desired: dict[str, Any], server_info: dict[str, Any]) -> None:
    """Refuse a theme the server does not list (P4).

    Keycloak accepts any theme name on a realm `PUT` and, at the first email, quietly
    renders its own templates instead. Measured on 26.7.3. So this is the only check
    between a Keycloak image without the `rec` theme and emails nobody branded.
    """
    themes = server_info.get("themes") or {}
    for key, kind in THEME_SETTINGS.items():
        name = desired.get(key)
        if name is None:
            continue
        listed = sorted(t.get("name") for t in themes.get(kind, []) if t.get("name"))
        if name not in listed:
            raise PlatformDeclarationError(
                f"{key}: {name!r} is not a {kind} theme this Keycloak lists ({listed}). "
                f"Deploy a Keycloak image that ships it before running bootstrap."
            )


# ---------------------------------------------------------------------------
# The account console's default client scopes
# ---------------------------------------------------------------------------

ACCOUNT_CONSOLE_CLIENT_ID = "account-console"

#: What Keycloak 26.7.3 gives `account-console` in a realm it creates itself
#: (`POST /admin/realms` with no clients, then `GET .../default-client-scopes`).
ACCOUNT_CONSOLE_DEFAULT_SCOPES = ("web-origins", "acr", "profile", "roles", "basic", "email")


async def _plan_account_console(kc: "KeycloakAdminClient") -> tuple[str | None, dict[str, str]]:
    """The account console's uuid and the missing default scopes, as name -> scope id.

    Refuses, before any write, when a scope it needs does not exist in the realm.
    A realm without the client (Keycloak always creates one) is left alone.
    """
    client = await kc.get_client_by_client_id(ACCOUNT_CONSOLE_CLIENT_ID)
    if client is None:
        logger.warning("realm has no %s client; its scopes are left alone", ACCOUNT_CONSOLE_CLIENT_ID)
        return None, {}
    have = {s.get("name") for s in await kc.get_client_default_scopes(client["id"])}
    missing: dict[str, str] = {}
    absent: list[str] = []
    for name in ACCOUNT_CONSOLE_DEFAULT_SCOPES:
        if name in have:
            continue
        scope = await kc.get_client_scope_by_name(name)
        if scope is None:
            absent.append(name)
        else:
            missing[name] = scope["id"]
    if absent:
        raise PlatformDeclarationError(
            f"{ACCOUNT_CONSOLE_CLIENT_ID} needs the client scopes {absent}, which this realm "
            f"does not have. Keycloak creates them with every realm; restore them before bootstrap."
        )
    return client["id"], missing


# ---------------------------------------------------------------------------
# SMTP (Phase 2b): from the environment, the password write-only
# ---------------------------------------------------------------------------

SMTP_SOURCE = "CELINE_KEYCLOAK_SMTP_*"

#: The `smtpServer` fields `bootstrap` compares. Absent and empty are the same value.
#: `password` is not among them: Keycloak returns it masked, so it cannot be compared.
SMTP_COMPARED_FIELDS = (
    "host", "port", "from", "fromDisplayName", "replyTo", "ssl", "starttls", "auth", "user",
)


def desired_smtp(smtp: "SmtpSettings") -> dict[str, str] | None:
    """The `smtpServer` representation the environment asks for, or None to leave it alone.

    Keycloak's own shape: every value a string. Optional fields left empty are omitted.
    """
    if not smtp.configured:
        return None
    required = {"CELINE_KEYCLOAK_SMTP_FROM": smtp.from_}
    if smtp.uses_auth:
        required["CELINE_KEYCLOAK_SMTP_USER"] = smtp.user
        required["CELINE_KEYCLOAK_SMTP_PASSWORD"] = smtp.password.get_secret_value()
    missing = sorted(name for name, value in required.items() if not value)
    if missing:
        raise PlatformDeclarationError(
            f"CELINE_KEYCLOAK_SMTP_HOST is set but {missing} are not"
        )
    rep = {
        "host": smtp.host.strip(),
        "port": str(smtp.port),
        "from": smtp.from_,
        "fromDisplayName": smtp.from_display_name,
        "replyTo": smtp.reply_to,
        "ssl": str(smtp.ssl).lower(),
        "starttls": str(smtp.starttls).lower(),
        "auth": str(smtp.uses_auth).lower(),
    }
    if smtp.uses_auth:
        rep["user"] = smtp.user
        rep["password"] = smtp.password.get_secret_value()
    return {k: v for k, v in rep.items() if v != ""}


def plan_smtp(desired: dict[str, str], current: dict[str, Any] | None) -> list[SettingChange]:
    """The compared `smtpServer` fields that differ. Never carries the password."""
    current = current or {}
    return [
        SettingChange(f"smtpServer.{name}", current.get(name) or None, desired.get(name) or None, SMTP_SOURCE)
        for name in SMTP_COMPARED_FIELDS
        if (current.get(name) or "") != (desired.get(name) or "")
    ]


def destructive(change: SettingChange) -> bool:
    """A change that turns something off or takes something away (Phase 4, decision 2).

    `bootstrap` never removes a key, so "remove or reset" is read as: a boolean going
    from true to false, or a list losing an entry. A new value, a longer or shorter
    lifespan and a different theme are updates. Outside dev such a plan needs
    `--allow-destructive` on that run, as `sync`'s pruning needs its confirmation.
    """
    if change.current is True and change.desired is False:
        return True
    if isinstance(change.current, list) and isinstance(change.desired, list):
        return bool(set(change.current) - set(change.desired))
    return False


@dataclass
class PlatformResult:
    """What a `bootstrap` run changed, or with `dry_run`, would change."""

    settings: list[SettingChange] = field(default_factory=list)
    roles_created: list[str] = field(default_factory=list)
    groups_created: list[str] = field(default_factory=list)
    #: (group path, realm role)
    role_mappings_added: list[tuple[str, str]] = field(default_factory=list)
    smtp: list[SettingChange] = field(default_factory=list)
    #: The SMTP password was (or would be) sent. Not a change: it cannot be compared,
    #: so it is sent on every run with SMTP authentication (requester, 2026-09-14).
    smtp_password_applied: bool = False

    #: The realm did not exist and was (or would be) created first.
    realm_created: bool = False
    #: The operator realm admin was (or would be) created, and put in this group.
    realm_admin_created: str | None = None
    realm_admin_group_added: tuple[str, str] | None = None

    #: Default client scopes added to the built-in `account-console` client.
    account_console_scopes_added: list[str] = field(default_factory=list)

    @property
    def destructive(self) -> list[SettingChange]:
        return [c for c in self.settings if destructive(c)]

    @property
    def changed(self) -> bool:
        return bool(
            self.realm_created
            or self.realm_admin_created
            or self.realm_admin_group_added
            or self.settings
            or self.roles_created
            or self.groups_created
            or self.role_mappings_added
            or self.smtp
            or self.account_console_scopes_added
        )


def desired_realm_settings(
    declaration: PlatformDeclaration, *, brute_force_protected: bool
) -> tuple[dict[str, Any], dict[str, str]]:
    """The declaration plus the per-environment keys, with a source for each."""
    desired = dict(declaration.realm_settings)
    sources = dict(declaration.sources)
    desired["bruteForceProtected"] = brute_force_protected
    sources["bruteForceProtected"] = "CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED"
    return desired, sources


async def converge_platform(
    kc: "KeycloakAdminClient",
    declaration: PlatformDeclaration,
    *,
    brute_force_protected: bool,
    dry_run: bool,
    smtp: "SmtpSettings | None" = None,
    realm_admin: "RealmAdminSettings | None" = None,
) -> PlatformResult:
    """Make the realm match the declaration, touching nothing it does not declare.

    Every check that can refuse runs before the first write, so a refused run leaves
    the realm as it found it.
    """
    desired, sources = desired_realm_settings(
        declaration, brute_force_protected=brute_force_protected
    )
    smtp_rep = desired_smtp(smtp) if smtp is not None else None
    check_themes(desired, await kc.get_server_info())

    realm = await kc.get_realm_settings()
    result = PlatformResult()
    result.settings = plan_realm_settings(desired, realm, sources)
    if smtp_rep is not None:
        result.smtp = plan_smtp(smtp_rep, realm.get("smtpServer"))
        result.smtp_password_applied = "password" in smtp_rep

    roles_missing: list[str] = []
    groups: dict[str, str | None] = {}
    for rg in declaration.role_groups:
        if rg.realm_role not in roles_missing and await kc.get_realm_role(rg.realm_role) is None:
            roles_missing.append(rg.realm_role)
        group = await kc.get_group_by_path(rg.path)
        groups[rg.path] = group["id"] if group else None

    result.roles_created = roles_missing
    for rg in declaration.role_groups:
        group_id = groups[rg.path]
        if group_id is None:
            result.groups_created.append(rg.path)
            result.role_mappings_added.append((rg.path, rg.realm_role))
        elif rg.realm_role not in await kc.get_group_realm_role_names(group_id):
            result.role_mappings_added.append((rg.path, rg.realm_role))

    console_id, console_missing = await _plan_account_console(kc)
    result.account_console_scopes_added = list(console_missing)

    admin_id: str | None = None
    if realm_admin is not None and realm_admin.configured:
        admin_id = await _plan_realm_admin(kc, declaration, realm_admin, groups, result)

    if dry_run:
        return result

    if result.settings:
        await kc.update_realm_settings({c.key: c.desired for c in result.settings})
        after = await kc.get_realm_settings()
        unstuck = [c.key for c in result.settings if not _same(c.key, after.get(c.key), c.desired)]
        if unstuck:
            raise PlatformDeclarationError(
                f"Keycloak accepted the realm update but these keys did not take: {unstuck}"
            )
        if desired.get("adminPermissionsEnabled") and not (
            await kc.get_admin_permissions_client_uuid()
        ):
            raise PlatformDeclarationError(
                "adminPermissionsEnabled is on but Keycloak reports no admin-permissions "
                "client. The server may be running without the ADMIN_FINE_GRAINED_AUTHZ_V2 feature."
            )

    if smtp_rep is not None and (result.smtp or result.smtp_password_applied):
        # Whole or not at all: Keycloak answers a partial smtpServer with a 400.
        await kc.update_realm_settings({"smtpServer": smtp_rep})
        unstuck = plan_smtp(smtp_rep, (await kc.get_realm_settings()).get("smtpServer"))
        if unstuck:
            raise PlatformDeclarationError(
                "Keycloak accepted smtpServer but these fields did not take: "
                f"{[c.key for c in unstuck]}"
            )

    for role in result.roles_created:
        await kc.create_realm_role(role)
    for rg in declaration.role_groups:
        if (rg.path, rg.realm_role) not in result.role_mappings_added:
            continue
        group_id = groups[rg.path]
        if group_id is None:
            group_id = await kc.create_group(rg.path.lstrip("/"))
        await kc.add_group_realm_role(group_id, rg.realm_role)

    if console_id is not None and console_missing:
        for scope_id in console_missing.values():
            await kc.add_client_default_scope(console_id, scope_id)
        _, unstuck = await _plan_account_console(kc)
        if unstuck:
            raise PlatformDeclarationError(
                f"Keycloak accepted the {ACCOUNT_CONSOLE_CLIENT_ID} scopes but these did not take: {sorted(unstuck)}"
            )

    if result.realm_admin_created or result.realm_admin_group_added:
        await _apply_realm_admin(kc, realm_admin, admin_id, result)

    return result


async def _plan_realm_admin(
    kc: "KeycloakAdminClient",
    declaration: PlatformDeclaration,
    admin: "RealmAdminSettings",
    groups: dict[str, str | None],
    result: PlatformResult,
) -> str | None:
    """Plan the operator realm admin, refusing before any write. Returns its id, if it exists."""
    username = admin.username.strip()
    if not admin.first_name.strip() or not admin.last_name.strip():
        raise PlatformDeclarationError(
            "CELINE_KEYCLOAK_REALM_ADMIN_FIRST_NAME and _LAST_NAME must not be empty: the "
            "realm's user profile requires both, and Keycloak refuses the sign-in without them"
        )
    group_known = admin.group in groups or await kc.get_group_by_path(admin.group) is not None
    if not group_known:
        raise PlatformDeclarationError(
            f"CELINE_KEYCLOAK_REALM_ADMIN_GROUP {admin.group!r} is neither a role group "
            f"platform.yaml declares nor a group the realm has"
        )
    user = await kc.get_user_by_username(username)
    if user is None:
        if not admin.password.get_secret_value():
            raise PlatformDeclarationError(
                f"realm admin {username!r} does not exist, and creating it needs "
                f"CELINE_KEYCLOAK_REALM_ADMIN_PASSWORD"
            )
        result.realm_admin_created = username
        result.realm_admin_group_added = (username, admin.group)
        return None
    paths = {g.get("path") for g in await kc.get_user_groups(user["id"])}
    if admin.group not in paths:
        result.realm_admin_group_added = (username, admin.group)
    return user["id"]


async def _apply_realm_admin(
    kc: "KeycloakAdminClient",
    admin: "RealmAdminSettings",
    admin_id: str | None,
    result: PlatformResult,
) -> None:
    if result.realm_admin_created:
        admin_id, _ = await kc.ensure_user(
            admin.username.strip(),
            email=admin.email or None,
            first_name=admin.first_name or None,
            last_name=admin.last_name or None,
            temporary_password=admin.password.get_secret_value(),
            temporary=False,
            email_verified=True,
        )
    group = await kc.get_group_by_path(admin.group)
    if group is None or admin_id is None:
        raise PlatformDeclarationError(f"realm admin group {admin.group!r} not found after converging")
    await kc.add_user_to_group(admin_id, group["id"])


# ---------------------------------------------------------------------------
# The check every other command makes
# ---------------------------------------------------------------------------


async def require_platform(
    kc: "KeycloakAdminClient",
    *,
    organizations: bool = False,
    admin_permissions: bool = False,
) -> None:
    """Refuse, naming `bootstrap`, unless the realm has the features a command needs.

    Read-only, so a dry run makes it too: a plan computed against a realm the
    command would refuse is not a plan.
    """
    missing: list[str] = []
    if organizations and not (await kc.get_realm_settings()).get("organizationsEnabled"):
        missing.append("organizationsEnabled")
    if admin_permissions and not await kc.get_admin_permissions_client_uuid():
        missing.append("adminPermissionsEnabled")
    if missing:
        raise PlatformNotReady(
            f"the realm is missing platform setting(s) {missing}. "
            f"Run `celine-policies keycloak bootstrap` first: platform.yaml declares them, "
            f"and bootstrap is the only command that writes them."
        )
