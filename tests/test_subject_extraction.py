from celine.policies.auth.subject import extract_subject_from_claims
from celine.policies.models import SubjectType


def test_extract_user_subject_with_groups_and_scopes():
    claims = {
        "sub": "user-123",
        "preferred_username": "alice",
        "realm_access": {"roles": ["viewers", "editors"]},
        "groups": ["/extra-group"],
        "scope": "dataset.query pipeline.execute",
        "azp": "frontend-client",
    }
    subject = extract_subject_from_claims(claims)
    assert subject.type == SubjectType.USER
    assert subject.id == "user-123"
    assert set(subject.groups) == {"viewers", "editors", "extra-group"}
    assert set(subject.scopes) == {"dataset.query", "pipeline.execute"}


def test_extract_service_subject_from_service_account_username():
    claims = {
        "preferred_username": "service-account-svc-forecast",
        "scope": "dataset.query mqtt.read",
        "azp": "svc-forecast",
    }
    subject = extract_subject_from_claims(claims)
    assert subject.type == SubjectType.SERVICE
    assert subject.id == "svc-forecast"
    assert subject.groups == []
    assert set(subject.scopes) == {"dataset.query", "mqtt.read"}


def test_extract_service_subject_from_client_id_claim():
    claims = {"client_id": "svc-admin", "scope": "dataset.admin"}
    subject = extract_subject_from_claims(claims)
    assert subject.type == SubjectType.SERVICE
    assert subject.id == "svc-admin"
