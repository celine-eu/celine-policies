"""Extract Subject from JWT claims.

Handles both human users (groups-based) and service accounts (scopes-based).
"""

from typing import Any
import logging

from celine.policies.models import Subject, SubjectType

logger = logging.getLogger(__name__)


class SubjectExtractor:
    """Extract Subject from JWT claims.

    Keycloak-specific claim mapping:
    - Users: groups from 'groups' claim
    - Services: identified by 'client_id' claim, scopes from 'scope' claim
    """

    def __init__(
        self,
        groups_claim: str = "groups",
        scope_claim: str = "scope",
        client_id_claim: str = "client_id",
    ):
        self._groups_claim = groups_claim
        self._scope_claim = scope_claim
        self._client_id_claim = client_id_claim

    def extract(self, claims: dict[str, Any]) -> Subject:
        is_service = self._client_id_claim in claims
        subject_type = SubjectType.SERVICE if is_service else SubjectType.USER

        if is_service:
            subject_id = claims.get(self._client_id_claim, claims.get("sub", "unknown"))
        else:
            subject_id = claims.get("sub", "unknown")

        groups = self._extract_groups(claims)
        scopes = self._extract_scopes(claims)

        subject = Subject(
            id=subject_id,
            type=subject_type,
            groups=groups,
            scopes=scopes,
            claims=claims,
        )

        logger.debug(
            "Subject extracted id=%s type=%s groups=%s scopes=%s",
            subject_id,
            subject_type.value,
            groups,
            scopes,
        )

        return subject

    def _extract_groups(self, claims: dict[str, Any]) -> list[str]:
        raw_groups = claims.get(self._groups_claim, [])
        if not isinstance(raw_groups, list):
            return []

        groups: list[str] = []
        for g in raw_groups:
            if isinstance(g, str):
                normalized = g.strip("/").split("/")[-1] if g else ""
                if normalized:
                    groups.append(normalized)
        return groups

    def _extract_scopes(self, claims: dict[str, Any]) -> list[str]:
        raw_scope = claims.get(self._scope_claim, "")

        if isinstance(raw_scope, str):
            return [s for s in raw_scope.split() if s]
        if isinstance(raw_scope, list):
            return [s for s in raw_scope if isinstance(s, str)]
        return []


def extract_subject_from_claims(claims: dict[str, Any]) -> Subject:
    return SubjectExtractor().extract(claims)
