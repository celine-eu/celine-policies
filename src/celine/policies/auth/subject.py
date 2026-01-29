"""Extract Subject from JWT claims.

Handles both human users (groups-based) and service accounts (scopes-based).
"""

from typing import Any

import structlog

from ..models import Subject, SubjectType

logger = structlog.get_logger()


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
        """Initialize extractor.

        Args:
            groups_claim: Claim containing group memberships
            scope_claim: Claim containing OAuth scopes (space-separated string)
            client_id_claim: Claim indicating service account
        """
        self._groups_claim = groups_claim
        self._scope_claim = scope_claim
        self._client_id_claim = client_id_claim

    def extract(self, claims: dict[str, Any]) -> Subject:
        """Extract Subject from JWT claims.

        Args:
            claims: Decoded JWT claims

        Returns:
            Subject instance
        """
        # Determine subject type
        is_service = self._client_id_claim in claims
        subject_type = SubjectType.SERVICE if is_service else SubjectType.USER

        # Get subject ID
        if is_service:
            subject_id = claims.get(self._client_id_claim, claims.get("sub", "unknown"))
        else:
            subject_id = claims.get("sub", "unknown")

        # Extract groups (primarily for users, but capture anyway)
        groups = self._extract_groups(claims)

        # Extract scopes (primarily for services)
        scopes = self._extract_scopes(claims)

        subject = Subject(
            id=subject_id,
            type=subject_type,
            groups=groups,
            scopes=scopes,
            claims=claims,
        )

        logger.debug(
            "Subject extracted",
            id=subject_id,
            type=subject_type.value,
            groups=groups,
            scopes=scopes,
        )

        return subject

    def _extract_groups(self, claims: dict[str, Any]) -> list[str]:
        """Extract groups from claims.

        Handles both full path (/admins) and short name (admins) formats.
        Normalizes to short names.
        """
        raw_groups = claims.get(self._groups_claim, [])

        if not isinstance(raw_groups, list):
            return []

        # Normalize: strip leading slashes, handle nested paths
        groups = []
        for g in raw_groups:
            if isinstance(g, str):
                # Remove leading slash and take last component
                # e.g., "/org/admins" -> "admins"
                # e.g., "admins" -> "admins"
                normalized = g.strip("/").split("/")[-1] if g else ""
                if normalized:
                    groups.append(normalized)

        return groups

    def _extract_scopes(self, claims: dict[str, Any]) -> list[str]:
        """Extract OAuth scopes from claims.

        Handles space-separated string format (OAuth 2.0 standard).
        """
        raw_scope = claims.get(self._scope_claim, "")

        if isinstance(raw_scope, str):
            # Space-separated string (OAuth 2.0 standard)
            return [s for s in raw_scope.split() if s]
        elif isinstance(raw_scope, list):
            # Some providers return list
            return [s for s in raw_scope if isinstance(s, str)]

        return []


def extract_subject_from_claims(claims: dict[str, Any]) -> Subject:
    """Convenience function to extract subject with default settings."""
    return SubjectExtractor().extract(claims)
