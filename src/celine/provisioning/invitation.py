"""Who gets an invitation email, which actions it carries, and where it may go.

Keycloak sends every email. What lives here is the decision in front of the send,
shared by the provisioning service and `keycloak sync-users` so the two cannot
disagree about it:

- **the actions**: an *invitation* (`UPDATE_PASSWORD` + `VERIFY_EMAIL`, the
  invitation lifespan) is for an account without a password; a *reset*
  (`UPDATE_PASSWORD` only, the short reset lifespan) is for one that has one.
  The caller names which it wants (`SendIntent`) and the service refuses a
  mismatch, so it never picks the email for the caller;
- **the address**: an account with no email address is never sent anything,
  and says so as `no_email` whatever the mode — it is not a dev-list refusal;
- **the recipient guard**: in `dev` mode only an address on the dev list is
  emailed, and everybody else is logged as a `WARNING` and reported as
  `not_on_dev_list`.

The guard defaults to `dev`, on purpose. Its failure is an invitation that did
not go out and says so in the log; the other default's failure is emailing real
people from a debugging session.

Nothing here imports FastAPI or typer, for the same reason as the rest of this
package: every `keycloak` subcommand imports it.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)

#: Why an upsert did, or did not, send an invitation. A stable reason code the
#: consumer translates for the operator who approved, rather than a boolean.
InvitationOutcome = Literal[
    "not_requested",
    "sent",
    "has_password",
    "not_on_dev_list",
    "account_disabled",
    "cooldown",
    "send_failed",
    "no_email",
]

#: What a caller of `POST .../invitation` asks for. Explicit, so the email
#: never differs from the button a person pressed (requester, 2026-09-14, A2).
SendIntent = Literal["invitation", "password_reset"]

EmailMode = Literal["deliver", "dev"]

UPDATE_PASSWORD = "UPDATE_PASSWORD"
VERIFY_EMAIL = "VERIFY_EMAIL"

#: An account with no password: set one, and prove the inbox while doing it.
INVITE_ACTIONS: tuple[str, ...] = (UPDATE_PASSWORD, VERIFY_EMAIL)
#: An account that has a password: replace it.
RESET_ACTIONS: tuple[str, ...] = (UPDATE_PASSWORD,)


def parse_recipients(value: str | Iterable[str] | None) -> frozenset[str]:
    """The dev list, from a comma-separated string or an iterable.

    Compared case-insensitively and stripped, because an address typed into an
    environment variable is not going to match Keycloak's casing by accident.
    """
    if value is None:
        return frozenset()
    items = value.split(",") if isinstance(value, str) else value
    return frozenset(item.strip().lower() for item in items if item and item.strip())


@dataclass(frozen=True)
class EmailPolicy:
    """Whether an address may be emailed in this deployment."""

    mode: EmailMode = "dev"
    dev_recipients: frozenset[str] = frozenset()

    def allows(self, address: str | None) -> bool:
        """Whether this address may be emailed. Callers check `has_address`
        first, so an account with no address is `no_email`, not a refusal."""
        if not has_address(address):
            return False
        if self.mode == "deliver":
            return True
        return address.strip().lower() in self.dev_recipients

    def refuse(self, who: str) -> None:
        """Log the refusal. Names the member, never an address list or a link."""
        logger.warning(
            "Email mode is 'dev' and %s is not on EMAIL_DEV_RECIPIENTS: "
            "no invitation was sent",
            who,
        )


def has_address(address: str | None) -> bool:
    """Whether an account carries an email address anything could be sent to."""
    return bool(address and address.strip())


def has_password(credentials: Iterable[dict]) -> bool:
    """Whether an account's credentials include a password."""
    return any(c.get("type") == "password" for c in credentials)
