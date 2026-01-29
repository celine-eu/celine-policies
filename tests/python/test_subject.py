"""Tests for subject extraction from JWT claims."""

import pytest

from celine_policies.auth.subject import SubjectExtractor, extract_subject_from_claims
from celine_policies.models import SubjectType


class TestSubjectExtractor:
    """Tests for SubjectExtractor."""

    def test_extract_user_from_claims(self, sample_user_claims):
        """Test extracting a user subject from JWT claims."""
        subject = extract_subject_from_claims(sample_user_claims)
        
        assert subject.id == "11111111-1111-1111-1111-111111111111"
        assert subject.type == SubjectType.USER
        assert "viewers" in subject.groups
        assert subject.scopes == []

    def test_extract_admin_from_claims(self, sample_admin_claims):
        """Test extracting an admin user subject."""
        subject = extract_subject_from_claims(sample_admin_claims)
        
        assert subject.type == SubjectType.USER
        assert "admins" in subject.groups

    def test_extract_service_from_claims(self, sample_service_claims):
        """Test extracting a service subject from JWT claims."""
        subject = extract_subject_from_claims(sample_service_claims)
        
        assert subject.id == "celine-cli"
        assert subject.type == SubjectType.SERVICE
        assert "dataset.query" in subject.scopes
        assert subject.groups == []  # Services don't have groups

    def test_extract_service_admin_scopes(self, sample_service_admin_claims):
        """Test service with admin scope."""
        subject = extract_subject_from_claims(sample_service_admin_claims)
        
        assert subject.type == SubjectType.SERVICE
        assert "dataset.query" in subject.scopes
        assert "dataset.admin" in subject.scopes

    def test_normalize_group_paths(self):
        """Test that group paths are normalized."""
        claims = {
            "sub": "user-1",
            "groups": ["/admins", "/org/managers", "editors"],
        }
        
        subject = extract_subject_from_claims(claims)
        
        # Should extract last component and strip slashes
        assert "admins" in subject.groups
        assert "managers" in subject.groups
        assert "editors" in subject.groups

    def test_scope_parsing(self):
        """Test parsing space-separated scopes."""
        claims = {
            "sub": "svc-1",
            "client_id": "test-client",
            "scope": "openid profile dataset.query dataset.admin",
        }
        
        subject = extract_subject_from_claims(claims)
        
        assert len(subject.scopes) == 4
        assert "dataset.query" in subject.scopes
        assert "dataset.admin" in subject.scopes

    def test_empty_groups_and_scopes(self):
        """Test handling of missing groups/scopes."""
        claims = {
            "sub": "user-1",
        }
        
        subject = extract_subject_from_claims(claims)
        
        assert subject.groups == []
        assert subject.scopes == []
        assert subject.type == SubjectType.USER
