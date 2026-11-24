"""An in-memory `GET/PUT /admin/realms/{realm}/events/config` (REQ-0024). Not a test module:
`test_*` files import it.

It answers the way Keycloak's `RealmAdminResource` and `RealmManager.updateRealmEventsConfig`
do (read in the 26.x source, 2026-11-24):

- `GET` reports Keycloak's default event types when the realm stores none: every type whose
  `saveByDefault` is true. So "no list stored" and "the default list" read the same;
- `PUT` sets `eventsEnabled` and `eventsExpiration` whatever the body says (an absent
  expiration becomes 0, "never"; an absent `eventsEnabled` fails), and sets the listeners,
  the types and the two admin flags only when the body names them.
"""

from __future__ import annotations

from typing import Any

from celine.policies.cli.keycloak.client import KeycloakError

#: A few of the types Keycloak saves by default; enough for the tests. `REFRESH_TOKEN`,
#: `INTROSPECT_TOKEN` and `USER_INFO_REQUEST` are not saved by default.
DEFAULT_EVENT_TYPES = (
    "LOGIN", "LOGIN_ERROR", "LOGOUT", "LOGOUT_ERROR", "CODE_TO_TOKEN", "CLIENT_LOGIN",
    "IMPERSONATE", "IMPERSONATE_ERROR", "UPDATE_PASSWORD", "UPDATE_CREDENTIAL",
)


class EventsFake:
    """The events configuration of one realm, as a new realm has it: nothing recorded,
    `jboss-logging` the only listener. Mix it into a fake realm that has `self.writes`."""

    def init_events(self, **stored: Any) -> None:
        self.events: dict[str, Any] = {
            "eventsEnabled": False,
            "eventsExpiration": 0,
            "eventsListeners": ["jboss-logging"],
            "enabledEventTypes": [],  # stored; empty means Keycloak's defaults
            "adminEventsEnabled": False,
            "adminEventsDetailsEnabled": False,
        }
        self.events.update(stored)
        self.events_puts: list[dict[str, Any]] = []
        #: False: Keycloak answers 204 and keeps what it had
        self.events_sticky = True

    async def get_events_config(self) -> dict[str, Any]:
        rep = {k: (list(v) if isinstance(v, list) else v) for k, v in self.events.items()}
        if not rep["enabledEventTypes"]:
            rep["enabledEventTypes"] = list(DEFAULT_EVENT_TYPES)
        if not rep["eventsExpiration"]:
            del rep["eventsExpiration"]
        return rep

    async def update_events_config(self, config: dict[str, Any]) -> None:
        self.events_puts.append(dict(config))
        self.writes.append(("events", tuple(sorted(config))))
        if config.get("eventsEnabled") is None:
            raise KeycloakError("eventsEnabled is required (NullPointerException)", status_code=500)
        if not self.events_sticky:
            return
        self.events["eventsEnabled"] = config["eventsEnabled"]
        self.events["eventsExpiration"] = config.get("eventsExpiration") or 0
        for key in ("eventsListeners", "enabledEventTypes", "adminEventsEnabled", "adminEventsDetailsEnabled"):
            if config.get(key) is not None:
                self.events[key] = list(config[key]) if isinstance(config[key], list) else config[key]
