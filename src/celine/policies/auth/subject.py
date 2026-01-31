"""JWT subject extraction.

The policy service distinguishes:
- user tokens (human principals, usually with groups/roles)
- service tokens (client credentials / service accounts)
"""

from __future__ import annotations

from typing import Any

from celine.policies.models import Subject, SubjectType


def _extract_groups(claims: dict[str, Any]) -> list[str]:
    groups: list[str] = []

    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict):
        roles = realm_access.get("roles")
        if isinstance(roles, list):
            groups.extend([str(r) for r in roles])

    grp_claim = claims.get("groups")
    if isinstance(grp_claim, list):
        groups.extend([str(g).lstrip("/") for g in grp_claim])

    return sorted(set(groups))


def _extract_scopes(claims: dict[str, Any]) -> list[str]:
    scope = claims.get("scope")
    if isinstance(scope, str):
        return sorted(set([s for s in scope.split() if s]))
    if isinstance(scope, list):
        return sorted(set([str(s) for s in scope if s]))
    return []


def _looks_like_service_account(claims: dict[str, Any]) -> bool:
    preferred_username = claims.get("preferred_username")
    if isinstance(preferred_username, str) and preferred_username.startswith("service-account-"):
        return True
    return False


def _extract_service_id(claims: dict[str, Any]) -> str:
    for key in ("client_id", "clientId"):
        val = claims.get(key)
        if isinstance(val, str) and val:
            return val

    azp = claims.get("azp")
    if isinstance(azp, str) and azp:
        return azp

    preferred_username = claims.get("preferred_username")
    if isinstance(preferred_username, str) and preferred_username.startswith("service-account-"):
        return preferred_username.replace("service-account-", "", 1)

    sub = claims.get("sub")
    return str(sub) if sub is not None else "unknown-service"


def extract_subject_from_claims(claims: dict[str, Any]) -> Subject:
    """Extract a Subject from JWT claims."""

    is_service = ("client_id" in claims) or ("clientId" in claims) or _looks_like_service_account(claims)

    if is_service:
        subject_id = _extract_service_id(claims)
        return Subject(
            id=subject_id,
            type=SubjectType.SERVICE,
            groups=[],
            scopes=_extract_scopes(claims),
            claims=claims,
        )

    subject_id = str(claims.get("sub") or claims.get("preferred_username") or "unknown-user")
    return Subject(
        id=subject_id,
        type=SubjectType.USER,
        groups=_extract_groups(claims),
        scopes=_extract_scopes(claims),
        claims=claims,
    )
