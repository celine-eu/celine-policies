"""Reading a REC bundle: what the registry says a community and its members are.

One parser, two sources. `GET /admin/export` on the live registry and a YAML file
an operator exported are the same bytes, so they are the same functions — which
is the property the whole source switch rests on: nothing below here can tell
which source it got. See ADR-0006.

These live beside the provisioning they feed rather than in the CLI that used to
own them, because the service reconciling a community reads exactly the same
bundle as `keycloak sync-users` does. `commands/_utils.py` re-exports them, so
the CLI's imports are unchanged.
"""

from __future__ import annotations

import logging

# Member statuses the registry uses: pending, active, suspended, inactive. Only one
# of them describes somebody who should be able to log in, and a row that names none
# is read as active — a hand-authored seed file omits the field entirely, and the
# registry's own schema makes it mandatory, so absent means "authored by hand" and
# never "pending".
ACTIVE_MEMBER_STATUS = "active"


def load_rec_participants(rec_doc: dict) -> list[dict]:
    """Extract participant records from a parsed REC registry bundle.

    Returns a list of dicts with keys: key, user_id, name, status.

    Takes the parsed document rather than a path because the same bundle arrives
    two ways — a file an operator exported, and `GET /admin/export` on the live
    registry. One parser for both is what keeps the two sources
    indistinguishable downstream; see `read_rec_documents`.

    **A member with no `user_id` is returned, not skipped.** It used to be
    dropped with a warning, which silently excluded exactly the seed members the
    file path exists to provision. The warning survives; `participant_username`
    decides what such a row is called.

    **Members whose status is not `active` are skipped.** The registry keys a
    member as pending before approval and suspended or inactive after
    withdrawal, and none of those is somebody who should be given a login. A row
    carrying no status at all is treated as active — see
    `ACTIVE_MEMBER_STATUS`. Nothing here disables an account that already
    exists: skipping provisioning and revoking access are different acts with
    different owners.
    """
    logger = logging.getLogger(__name__)
    # Support both "members" (new schema) and "participants" (legacy)
    participants_raw = rec_doc.get("members") or rec_doc.get("participants") or {}

    participants = []
    for key, data in participants_raw.items():
        data = data or {}
        status = data.get("status") or ACTIVE_MEMBER_STATUS
        if status != ACTIVE_MEMBER_STATUS:
            logger.info("Member %s is %s, not active — skipping", key, status)
            continue
        user_id = data.get("user_id")
        if not user_id:
            logger.warning(
                "Member %s has no user_id — provisioning it under a name derived "
                "from its key, which is not what it will authenticate as if the "
                "registry later gives it one",
                key,
            )
        participants.append(
            {
                "key": key,
                "user_id": user_id,
                "name": data.get("name", key),
                "status": status,
            }
        )
    return participants


def load_rec_operators(rec_doc: dict) -> list[dict]:
    """Extract DSO operator records from a parsed bundle (community.operators).

    Returns a list of dicts: id, name, country, contact.
    Operators without an id are skipped.
    """
    logger = logging.getLogger(__name__)
    operators_raw = (rec_doc.get("community") or {}).get("operators", {})
    operators = []
    for op_id, data in (operators_raw or {}).items():
        if not op_id:
            logger.warning("Operator entry without id — skipping")
            continue
        operators.append(
            {
                "id": op_id,
                "name": data.get("name", op_id),
                "country": data.get("country"),
                "contact": data.get("contact"),
            }
        )
    return operators


def load_rec_community_info(rec_doc: dict, *, source: str = "REC bundle") -> dict:
    """Extract community metadata from a parsed REC registry bundle.

    Returns a dict with keys: id, name, description, type.
    Raises ValueError if community.id is missing.

    `source` names the file or URL the document came from, because the refusal
    below is the one a person has to act on and "a document" does not say which.
    """
    community = rec_doc.get("community") or {}
    rec_id = community.get("id")
    if not rec_id:
        raise ValueError(f"{source} is missing community.id")
    return {
        "id": rec_id,
        "name": community.get("name", rec_id),
        "description": community.get("description", ""),
        "type": community.get("type", "rec"),
    }


def derive_username(participant_key: str) -> str:
    """Stable Keycloak username from the participant key (e.g. 'gl-00001').

    Unique within the community, no PII, safe to hand out during demos.

    **A fallback, not the rule.** `participant_username` prefers the `user_id`
    the registry holds; this is what a row with none is called.
    """
    return participant_key.lower()


def participant_username(participant: dict) -> str:
    """What this member authenticates as: the `user_id` the registry row holds.

    `Member.user_id` is a Keycloak **username** — the value `preferred_username`
    carries — and the registry resolves every self-service call by matching it.
    So the row that owns the value is what names the account, and this command
    derives nothing when it has one.

    It used to derive always, and against a hand-maintained file that was
    invisible because the same hand wrote both columns. It is not invisible
    against the live registry: `../onboarding` writes `key = submission.ref`
    (`20260912-a3f9c2`) and `user_id` = the username Keycloak returned, so
    deriving would create a second account beside the one the participant
    already signs in with — once per onboarded member.

    `derive_username(key)` survives for a row carrying no `user_id`, which the
    registry path cannot produce (the column is `nullable=False`) and which only
    a hand-authored seed file has.

    **The two conventions are not converged and do not need to be.** The
    username is a static handle the participant does not choose and does not
    change — it is what an account is *matched* by, with email as a fallback
    where a lookup offers one. So its shape carries no meaning: `gl-00001` from
    a seed and `a.person@example.org` from onboarding are equally correct, and
    the second is not "an email" — it is a string onboarding happened to take
    from one. Nothing may parse it, normalise it, or infer anything from it.

    What matters is only that neither writer is guessing: the value is read from
    the row that owns it, verbatim.
    """
    user_id = (participant.get("user_id") or "").strip()
    if user_id:
        return user_id
    return derive_username(participant["key"])
