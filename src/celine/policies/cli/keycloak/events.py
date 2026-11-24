"""The realm's event recording, as `bootstrap` converges it (REQ-0024).

A team member who impersonates a mirrored member acts in that member's name; Keycloak's
`IMPERSONATE` event is the only record of who did. Sign-ins and admin changes are the access
audit the platform keeps. A new realm records none of them (`eventsEnabled` and
`adminEventsEnabled` are false), and nothing wrote them, so `bootstrap` owns them: on unless
the environment is exactly `dev`, `CELINE_KEYCLOAK_EVENTS_ENABLED` overriding either way.

## What is converged (`GET/PUT /admin/realms/{realm}/events/config`)

- `eventsEnabled` and `adminEventsEnabled`: true.
- `enabledEventTypes`: **at least** the declared types. Keycloak stores no list on a new realm
  and then records its own default set (every type whose `saveByDefault` is true: sign-in,
  sign-out, impersonation, credential changes; not token refresh, introspection or userinfo),
  and `GET` reports that set. The required types are in it, so on such a realm no list is
  written and the realm keeps following Keycloak's defaults across upgrades. A stored list
  missing one gets it added; a type it holds is never removed.
- `eventsExpiration`: the declared seconds. `null` leaves the realm's own value.
- `adminEventsDetailsEnabled`: as declared, off in the image. The details are the request's
  representation, which on a user or a member carries personal data.
- `eventsListeners`: never changed, sent back as read (`jboss-logging` stays).

## Why the write sends the whole configuration

`RealmManager.updateRealmEventsConfig` (Keycloak 26.x) sets `eventsEnabled` from the body
unconditionally and `eventsExpiration` to 0 ("never") when the body leaves it out. The other
fields are set only when present. So a write always carries both, and the listeners as read.

Off, the realm's events are left as they are: `bootstrap` never turns recording off.
Who can: `manage-events` and `view-events` in the realm, which the bootstrap client (master
`admin`) holds and the admin CLI client does not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from celine.policies.cli.keycloak.platform import (
    PlatformDeclarationError,
    SettingChange,
)

if TYPE_CHECKING:
    from celine.policies.cli.keycloak.client import KeycloakAdminClient

#: The switch, and the source of the on/off changes in a report.
EVENTS_SOURCE = "CELINE_KEYCLOAK_EVENTS_ENABLED"
#: The variable that overrides the declared expiration (`null`: leave the realm's).
EVENTS_EXPIRATION_OVERRIDE = "CELINE_KEYCLOAK_PLATFORM_EVENTS_EXPIRATION"
#: The types a declaration must require: who impersonated whom, and every sign-in.
REQUIRED_EVENT_TYPES = ("IMPERSONATE", "IMPERSONATE_ERROR", "LOGIN", "LOGIN_ERROR")
#: One year: the access audit's retention, held in Keycloak until a log store keeps it.
DEFAULT_EVENTS_EXPIRATION = 365 * 24 * 3600

#: The `events` block of `platform.yaml`, and what each key is.
EVENTS_KEYS = ("user_event_types", "expiration", "admin_details")
#: Prefix of a report key, so an events field is never read as a realm key.
KEY_PREFIX = "events."

_EVENT_TYPE = re.compile(r"^[A-Z][A-Z0-9_]*$")


@dataclass(frozen=True)
class EventsDeclaration:
    """What `bootstrap` converges when events are on."""

    required_types: tuple[str, ...] = REQUIRED_EVENT_TYPES
    #: seconds; None leaves the realm's own value
    expiration: int | None = DEFAULT_EVENTS_EXPIRATION
    admin_details: bool = False


def _seconds(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def events_from_yaml(path: Path | str, raw: Any) -> EventsDeclaration:
    """The `events` block of a declaration, checked. Absent: the defaults above."""
    if raw is None:
        return EventsDeclaration()
    if not isinstance(raw, dict):
        raise PlatformDeclarationError(f"{path}: events must be a mapping with {list(EVENTS_KEYS)}")
    unknown = sorted(set(raw) - set(EVENTS_KEYS))
    if unknown:
        raise PlatformDeclarationError(
            f"{path}: events.{unknown[0]} is not accepted (accepted: {list(EVENTS_KEYS)}); "
            f"the realm's listeners are never changed"
        )
    types = raw.get("user_event_types", list(REQUIRED_EVENT_TYPES))
    if (
        not isinstance(types, list)
        or not types
        or not all(isinstance(t, str) and _EVENT_TYPE.match(t) for t in types)
        or len(set(types)) != len(types)
    ):
        raise PlatformDeclarationError(
            f"{path}: events.user_event_types must be a list of distinct Keycloak event types "
            f"(upper case, like LOGIN), got {types!r}"
        )
    missing = [t for t in REQUIRED_EVENT_TYPES if t not in types]
    if missing:
        raise PlatformDeclarationError(
            f"{path}: events.user_event_types must name {missing} too: the record of who "
            f"impersonated whom, and of every sign-in"
        )
    expiration = raw.get("expiration", DEFAULT_EVENTS_EXPIRATION)
    if expiration is not None and not _seconds(expiration):
        raise PlatformDeclarationError(
            f"{path}: events.expiration must be a non-negative integer (seconds), got {expiration!r}"
        )
    details = raw.get("admin_details", False)
    if not isinstance(details, bool):
        raise PlatformDeclarationError(f"{path}: events.admin_details must be a boolean, got {details!r}")
    return EventsDeclaration(tuple(types), expiration, details)


def expiration_from_env(raw: str) -> int | None:
    """`CELINE_KEYCLOAK_PLATFORM_EVENTS_EXPIRATION`: seconds, or `null` for the realm's own."""
    text = raw.strip()
    if text.lower() == "null":
        return None
    if not text.isdigit():
        raise PlatformDeclarationError(
            f"{EVENTS_EXPIRATION_OVERRIDE}: must be a non-negative integer (seconds) or null, got {raw!r}"
        )
    return int(text)


@dataclass
class EventsPlan:
    """What converging the events would write, and the changes to report."""

    changes: list[SettingChange] = field(default_factory=list)
    #: the body of the `PUT`, None when nothing changes
    body: dict[str, Any] | None = None
    #: why the events were not managed on this run
    skipped: str | None = None


async def plan_events(
    kc: KeycloakAdminClient,
    declaration: EventsDeclaration,
    *,
    enabled: bool,
    sources: dict[str, str] | None = None,
) -> EventsPlan:
    """Read the realm's events configuration and plan the convergence. Writes nothing.

    `sources` names where the declared values came from (`events.expiration` -> a file or the
    override); the switch's changes name `EVENTS_SOURCE`.
    """
    if not enabled:
        return EventsPlan(skipped=f"ENV=dev ({EVENTS_SOURCE} off)")
    sources = sources or {}
    declared_from = sources.get("events", "platform.yaml")
    current = await kc.get_events_config()
    plan = EventsPlan()

    def change(key: str, now: Any, want: Any, source: str) -> None:
        plan.changes.append(SettingChange(KEY_PREFIX + key, now, want, source))

    for key in ("eventsEnabled", "adminEventsEnabled"):
        if current.get(key) is not True:
            change(key, bool(current.get(key)), True, EVENTS_SOURCE)

    have = list(current.get("enabledEventTypes") or [])
    missing = [t for t in declaration.required_types if t not in have]
    types = [*have, *missing] if missing else None
    if types is not None:
        change("enabledEventTypes", have, types, declared_from)

    now_expiration = current.get("eventsExpiration") or 0
    expiration = now_expiration if declaration.expiration is None else declaration.expiration
    if expiration != now_expiration:
        change("eventsExpiration", now_expiration, expiration,
               sources.get("events.expiration", declared_from))

    details = bool(current.get("adminEventsDetailsEnabled"))
    if details != declaration.admin_details:
        change("adminEventsDetailsEnabled", details, declaration.admin_details, declared_from)

    if plan.changes:
        body: dict[str, Any] = {
            "eventsEnabled": True,
            "adminEventsEnabled": True,
            "adminEventsDetailsEnabled": declaration.admin_details,
            "eventsExpiration": expiration,
        }
        if current.get("eventsListeners") is not None:
            body["eventsListeners"] = list(current["eventsListeners"])
        if types is not None:
            body["enabledEventTypes"] = types
        plan.body = body
    return plan


async def apply_events(kc: KeycloakAdminClient, plan: EventsPlan) -> None:
    """Write `plan`, then read it back: a field that did not take is an error."""
    if plan.body is None:
        return
    await kc.update_events_config(plan.body)
    after = await kc.get_events_config()
    unstuck = [
        c.key for c in plan.changes
        if not _took(c.key.removeprefix(KEY_PREFIX), after, c.desired)
    ]
    if unstuck:
        raise PlatformDeclarationError(
            f"Keycloak accepted the events configuration but these did not take: {unstuck}"
        )


def _took(key: str, after: dict[str, Any], desired: Any) -> bool:
    if key == "enabledEventTypes":
        return set(desired) <= set(after.get(key) or [])
    if key == "eventsExpiration":
        return (after.get(key) or 0) == desired
    return bool(after.get(key)) == desired
