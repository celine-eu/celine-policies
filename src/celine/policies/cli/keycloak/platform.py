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

## The platform-wide grant, and what it replaced (ADR-0012)

Exactly two levels. The realm role `platform-admin` is the only platform-wide grant; an
organization's own groups count only inside it. `bootstrap` creates the role, gives it directly
to the operator realm admin and to `platform_admin.users`, and takes it off any group or
composite role that would hand it to everyone in it. It deletes the realm groups and roles
`retired` lists — the old `/admins`-style role groups — from whatever state the realm is in.
Those deletions are the declaration, so `--allow-destructive` does not gate them.

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

from celine.sdk.auth import PLATFORM_ADMIN_ROLE

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

#: The only realm keys a deployment overlay may change. It may also list the deployment's
#: platform administrators, `platform_admin.users`, and nothing else of the declaration.
OVERLAY_REALM_SETTINGS = frozenset({"supportedLocales"})
PLATFORM_ADMINS_KEY = "platform_admin.users"

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

_TOP_LEVEL_KEYS = frozenset({"realm_settings", "platform_admin", "retired"})

#: Realm roles Keycloak owns. `retired` may not name one: deleting it breaks every login.
BUILTIN_REALM_ROLES = frozenset({"offline_access", "uma_authorization"})
BUILTIN_REALM_ROLE_PREFIX = "default-roles-"


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


@dataclass
class PlatformDeclaration:
    """`platform.yaml` with its overlays applied, and where each value came from."""

    realm_settings: dict[str, Any] = field(default_factory=dict)
    #: The platform-wide realm role. Always `PLATFORM_ADMIN_ROLE`: the loader refuses another.
    platform_admin_role: str = PLATFORM_ADMIN_ROLE
    #: Usernames that hold it directly, beside the operator realm admin.
    platform_admins: list[str] = field(default_factory=list)
    #: Top-level realm group paths and realm role names bootstrap deletes when present.
    retired_groups: list[str] = field(default_factory=list)
    retired_roles: list[str] = field(default_factory=list)
    #: realm key -> the file that set it last; `platform_admin.users` too
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


def _names(path: "Path | str", key: str, raw: Any) -> list[str]:
    """A list of distinct non-empty strings, or a refusal naming `key`."""
    if raw is None:
        return []
    if (
        not isinstance(raw, list)
        or not all(isinstance(v, str) and v.strip() for v in raw)
        or len({v.strip() for v in raw}) != len(raw)
    ):
        raise PlatformDeclarationError(f"{path}: {key} must be a list of distinct names, got {raw!r}")
    return [v.strip() for v in raw]


def _platform_admin(path: Path, data: dict[str, Any]) -> tuple[str, list[str]]:
    """`platform_admin`: the role, which must be the SDK's, and the users who hold it."""
    raw = data.get("platform_admin")
    if raw is None:
        raise PlatformDeclarationError(
            f"{path}: platform_admin is required: it declares the realm role "
            f"{PLATFORM_ADMIN_ROLE!r}, the only platform-wide grant"
        )
    if not isinstance(raw, dict) or not set(raw) <= {"role", "users"}:
        raise PlatformDeclarationError(
            f"{path}: platform_admin must be a mapping with `role` and `users`"
        )
    role = raw.get("role")
    if role != PLATFORM_ADMIN_ROLE:
        raise PlatformDeclarationError(
            f"{path}: platform_admin.role must be {PLATFORM_ADMIN_ROLE!r}, the name every "
            f"service reads from realm_access.roles; got {role!r}"
        )
    return role, _names(path, "platform_admin.users", raw.get("users"))


def _retired(path: Path, data: dict[str, Any]) -> tuple[list[str], list[str]]:
    """`retired`: the realm groups and roles bootstrap deletes. Never a built-in or the grant."""
    raw = data.get("retired") or {}
    if not isinstance(raw, dict) or not set(raw) <= {"realm_groups", "realm_roles"}:
        raise PlatformDeclarationError(
            f"{path}: retired must be a mapping with `realm_groups` and `realm_roles`"
        )
    groups = _names(path, "retired.realm_groups", raw.get("realm_groups"))
    for group_path in groups:
        if not group_path.startswith("/") or "/" in group_path[1:] or len(group_path) < 2:
            raise PlatformDeclarationError(
                f"{path}: retired.realm_groups must name top-level group paths like /admins, "
                f"got {group_path!r}"
            )
    roles = _names(path, "retired.realm_roles", raw.get("realm_roles"))
    for role in roles:
        if role == PLATFORM_ADMIN_ROLE:
            raise PlatformDeclarationError(
                f"{path}: retired.realm_roles names {PLATFORM_ADMIN_ROLE!r}, the platform grant"
            )
        if role in BUILTIN_REALM_ROLES or role.startswith(BUILTIN_REALM_ROLE_PREFIX):
            raise PlatformDeclarationError(
                f"{path}: retired.realm_roles names {role!r}, a role Keycloak owns"
            )
    return groups, roles


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
    and `platform_admin.users` only. Key-level merge, last wins, and a list replaces a list. The environment
    (`apply_env_overrides`) wins over both. Every check runs on the merged result,
    before `bootstrap` reads anything from Keycloak.
    """
    data = _read_mapping(path)
    settings = _realm_settings(path, data)
    role, admins = _platform_admin(path, data)
    retired_groups, retired_roles = _retired(path, data)
    declaration = PlatformDeclaration(
        realm_settings=settings,
        platform_admin_role=role,
        platform_admins=admins,
        retired_groups=retired_groups,
        retired_roles=retired_roles,
        sources={key: str(path) for key in settings},
        platform_file=str(path),
    )
    declaration.sources[PLATFORM_ADMINS_KEY] = str(path)

    for overlay in overlays:
        odata = _read_mapping(overlay)
        if "retired" in odata:
            raise PlatformDeclarationError(
                f"{overlay}: an overlay may not change retired; it may change only "
                f"{sorted(OVERLAY_REALM_SETTINGS)} and {PLATFORM_ADMINS_KEY}"
            )
        if "platform_admin" in odata:
            padmin = odata["platform_admin"]
            if not isinstance(padmin, dict) or set(padmin) != {"users"}:
                raise PlatformDeclarationError(
                    f"{overlay}: an overlay may change {PLATFORM_ADMINS_KEY} only, "
                    f"never the role's name"
                )
            declaration.platform_admins = _names(overlay, PLATFORM_ADMINS_KEY, padmin["users"])
            declaration.sources[PLATFORM_ADMINS_KEY] = str(overlay)
        osettings = _realm_settings(overlay, odata)
        refused = sorted(set(osettings) - OVERLAY_REALM_SETTINGS)
        if refused:
            raise PlatformDeclarationError(
                f"{overlay}: an overlay may change only {sorted(OVERLAY_REALM_SETTINGS)} "
                f"and {PLATFORM_ADMINS_KEY}; it names {refused}"
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
    # The admin second factor turned off: a custom browser flow unbound for Keycloak's own
    # (REQ-0015, REQ-0016).
    if change.key == "browserFlow" and change.desired == "browser" and change.current not in (None, "browser"):
        return True
    return False


@dataclass
class PlatformResult:
    """What a `bootstrap` run changed, or with `dry_run`, would change."""

    settings: list[SettingChange] = field(default_factory=list)
    smtp: list[SettingChange] = field(default_factory=list)
    #: The SMTP password was (or would be) sent. Not a change: it cannot be compared,
    #: so it is sent on every run with SMTP authentication (requester, 2026-09-14).
    smtp_password_applied: bool = False

    #: The realm did not exist and was (or would be) created first.
    realm_created: bool = False
    #: The operator realm admin was (or would be) created.
    realm_admin_created: str | None = None

    #: The platform-wide role (`platform-admin`) was (or would be) created.
    platform_admin_role_created: bool = False
    #: Usernames given the role directly, the realm admin included.
    platform_admins_granted: list[str] = field(default_factory=list)
    #: Realm groups the role was mapped onto, by path.
    platform_admin_unmapped_groups: list[str] = field(default_factory=list)
    #: Composite realm roles (the realm's default roles among them) it was taken out of.
    platform_admin_unmapped_composites: list[str] = field(default_factory=list)
    #: Retired realm groups and realm roles deleted (REQ-0012).
    groups_removed: list[str] = field(default_factory=list)
    roles_removed: list[str] = field(default_factory=list)

    #: Reported, never a change. Declared usernames the realm does not have yet, and
    #: direct holders of the role nobody declared (kept: bootstrap does not revoke).
    platform_admins_missing: list[str] = field(default_factory=list)
    platform_admins_undeclared: list[str] = field(default_factory=list)

    #: Default client scopes added to the built-in `account-console` client.
    account_console_scopes_added: list[str] = field(default_factory=list)

    #: The platform admin's second factor: the realm's browser flow (REQ-0015).
    admin_mfa: list[SettingChange] = field(default_factory=list)
    #: The master realm (REQ-0016): the bootstrap client, then the hardening.
    master_client: list[SettingChange] = field(default_factory=list)
    master: list[SettingChange] = field(default_factory=list)
    #: Who this run signed in to master as, and why master was not hardened, for the report.
    master_session: str | None = None
    master_skipped: str | None = None

    @property
    def destructive(self) -> list[SettingChange]:
        return [c for c in [*self.settings, *self.admin_mfa, *self.master] if destructive(c)]

    @property
    def changed(self) -> bool:
        return bool(
            self.realm_created
            or self.realm_admin_created
            or self.settings
            or self.smtp
            or self.platform_admin_role_created
            or self.platform_admins_granted
            or self.platform_admin_unmapped_groups
            or self.platform_admin_unmapped_composites
            or self.groups_removed
            or self.roles_removed
            or self.account_console_scopes_added
            or self.admin_mfa
            or self.master_client
            or self.master
        )


def desired_realm_settings(
    declaration: PlatformDeclaration, *, brute_force_protected: bool
) -> tuple[dict[str, Any], dict[str, str]]:
    """The declaration plus the per-environment keys, with a source for each."""
    desired = dict(declaration.realm_settings)
    sources = {k: v for k, v in declaration.sources.items() if k in desired}
    desired["bruteForceProtected"] = brute_force_protected
    sources["bruteForceProtected"] = "CELINE_KEYCLOAK_BRUTE_FORCE_ENABLED"
    return desired, sources


@dataclass
class _RolePlan:
    """The ids the writes of the platform role and the retired objects need."""

    #: retired group path -> id
    groups: dict[str, str] = field(default_factory=dict)
    #: group id -> its report label, for the role's group mappings to remove
    shared_groups: dict[str, str] = field(default_factory=dict)
    #: composite role id -> its name
    composites: dict[str, str] = field(default_factory=dict)
    #: username -> user id, for the grants; None for a realm admin still to be created
    grants: dict[str, str | None] = field(default_factory=dict)


def _is_realm_group(group: dict[str, Any] | None) -> bool:
    """A top-level realm group. An organization's group has a parent, and is never ours."""
    return bool(group) and not group.get("parentId")


async def _plan_platform_role(
    kc: "KeycloakAdminClient",
    declaration: PlatformDeclaration,
    result: PlatformResult,
    realm_admin: "RealmAdminSettings | None",
) -> _RolePlan:
    """Read everything the role and the retired objects need. Writes nothing."""
    plan = _RolePlan()
    role_name = declaration.platform_admin_role

    for path in declaration.retired_groups:
        group = await kc.get_group_by_path(path)
        if _is_realm_group(group):
            plan.groups[path] = group["id"]
            result.groups_removed.append(path)
    for name in declaration.retired_roles:
        if await kc.get_realm_role(name) is not None:
            result.roles_removed.append(name)

    role = await kc.get_realm_role(role_name)
    result.platform_admin_role_created = role is None

    if role is not None:
        # Anything that would hand the role to everyone in it: a realm group, or a
        # composite role such as the realm's default roles. An organization's group is
        # not among them: on 26.7.3 a realm role mapped onto one (only the Organization
        # API can) reaches no member's token, and `…/roles/{role}/groups` does not list it.
        for group in await kc.get_realm_role_groups(role_name):
            if group["id"] in plan.groups.values() or not _is_realm_group(group):
                continue  # deleted with the retired group / not a realm group
            plan.shared_groups[group["id"]] = group.get("path") or group.get("name") or group["id"]
        for composite in await kc.list_realm_roles():
            if not composite.get("composite") or composite.get("name") in result.roles_removed:
                continue
            if role_name in await kc.get_role_composite_realm_role_names(composite["id"]):
                plan.composites[composite["id"]] = composite["name"]
        result.platform_admin_unmapped_groups = sorted(plan.shared_groups.values())
        result.platform_admin_unmapped_composites = sorted(plan.composites.values())

    declared: list[str] = []
    if realm_admin is not None and realm_admin.configured:
        admin_id = await _plan_realm_admin(kc, realm_admin, result)
        declared.append(realm_admin.username.strip())
        if admin_id is None or role is None or role_name not in await kc.get_user_realm_role_names(admin_id):
            plan.grants[declared[-1]] = admin_id
    for username in declaration.platform_admins:
        if username in declared:
            continue
        declared.append(username)
        user = await kc.get_user_by_username(username)
        if user is None:
            result.platform_admins_missing.append(username)
            continue
        if role is None or role_name not in await kc.get_user_realm_role_names(user["id"]):
            plan.grants[username] = user["id"]
    result.platform_admins_granted = list(plan.grants)

    if role is not None:
        holders = {u.get("username") for u in await kc.get_realm_role_users(role_name)}
        result.platform_admins_undeclared = sorted(h for h in holders if h and h not in declared)
    return plan


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

    role_plan = await _plan_platform_role(kc, declaration, result, realm_admin)

    console_id, console_missing = await _plan_account_console(kc)
    result.account_console_scopes_added = list(console_missing)

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

    # The retired level first: a group goes with its memberships and role mappings, a
    # role with every mapping of it.
    for group_id in role_plan.groups.values():
        await kc.delete_group(group_id)
    for name in result.roles_removed:
        await kc.delete_realm_role(name)

    role_name = declaration.platform_admin_role
    if result.platform_admin_role_created:
        await kc.create_realm_role(role_name)
    for group_id in role_plan.shared_groups:
        await kc.remove_group_realm_role(group_id, role_name)
    for composite_id in role_plan.composites:
        await kc.remove_role_composite_realm_role(composite_id, role_name)

    if result.realm_admin_created:
        admin_id = await _apply_realm_admin(kc, realm_admin)
        role_plan.grants[realm_admin.username.strip()] = admin_id
    for username, user_id in role_plan.grants.items():
        if user_id is None:
            raise PlatformDeclarationError(f"user {username!r} not found after converging")
        await kc.add_user_realm_role(user_id, role_name)

    if console_id is not None and console_missing:
        for scope_id in console_missing.values():
            await kc.add_client_default_scope(console_id, scope_id)
        _, unstuck = await _plan_account_console(kc)
        if unstuck:
            raise PlatformDeclarationError(
                f"Keycloak accepted the {ACCOUNT_CONSOLE_CLIENT_ID} scopes but these did not take: {sorted(unstuck)}"
            )

    return result


async def _plan_realm_admin(
    kc: "KeycloakAdminClient",
    admin: "RealmAdminSettings",
    result: PlatformResult,
) -> str | None:
    """Plan the operator realm admin, refusing before any write. Returns its id, if it exists."""
    username = admin.username.strip()
    if not admin.first_name.strip() or not admin.last_name.strip():
        raise PlatformDeclarationError(
            "CELINE_KEYCLOAK_REALM_ADMIN_FIRST_NAME and _LAST_NAME must not be empty: the "
            "realm's user profile requires both, and Keycloak refuses the sign-in without them"
        )
    user = await kc.get_user_by_username(username)
    if user is None:
        if not admin.password.get_secret_value():
            raise PlatformDeclarationError(
                f"realm admin {username!r} does not exist, and creating it needs "
                f"CELINE_KEYCLOAK_REALM_ADMIN_PASSWORD"
            )
        result.realm_admin_created = username
        return None
    return user["id"]


async def _apply_realm_admin(kc: "KeycloakAdminClient", admin: "RealmAdminSettings") -> str:
    admin_id, _ = await kc.ensure_user(
        admin.username.strip(),
        email=admin.email or None,
        first_name=admin.first_name or None,
        last_name=admin.last_name or None,
        temporary_password=admin.password.get_secret_value(),
        temporary=False,
        email_verified=True,
    )
    return admin_id


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
