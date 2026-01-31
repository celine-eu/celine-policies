from celine.policies.auth.subject import extract_subject_from_claims
from celine.policies.models import SubjectType


def test_extract_user_subject_from_groups():
    claims = {"sub": "user-1", "groups": ["/admins", "/users"]}
    subj = extract_subject_from_claims(claims)
    assert subj.id == "user-1"
    assert subj.type == SubjectType.USER
    assert set(subj.groups) == {"admins", "users"}


def test_extract_service_subject_from_client_id_and_scopes():
    claims = {"sub": "svc-sub", "client_id": "svc-1", "scope": "read write"}
    subj = extract_subject_from_claims(claims)
    assert subj.id == "svc-1"
    assert subj.type == SubjectType.SERVICE
    assert subj.scopes == ["read", "write"]


def test_extract_subject_handles_bad_claim_types():
    claims = {"sub": "user-2", "groups": "not-a-list", "scope": ["a", 1, None]}
    subj = extract_subject_from_claims(claims)
    assert subj.id == "user-2"
    assert subj.groups == []
    assert subj.scopes == ["1", "a"]
