"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path


@pytest.fixture
def policies_dir() -> Path:
    """Path to test policies."""
    return Path(__file__).parent.parent / "policies"


@pytest.fixture
def data_dir() -> Path:
    """Path to test data."""
    return Path(__file__).parent.parent / "data"


@pytest.fixture
def sample_user_claims() -> dict:
    """Sample JWT claims for a user."""
    return {
        "sub": "11111111-1111-1111-1111-111111111111",
        "preferred_username": "testuser",
        "email": "test@celine.localhost",
        "groups": ["viewers"],
        "realm_access": {"roles": ["viewer"]},
        "iat": 1704067200,
        "exp": 1704153600,
        "iss": "http://keycloak.celine.localhost/realms/celine",
    }


@pytest.fixture
def sample_admin_claims() -> dict:
    """Sample JWT claims for an admin user."""
    return {
        "sub": "22222222-2222-2222-2222-222222222222",
        "preferred_username": "admin",
        "email": "admin@celine.localhost",
        "groups": ["admins"],
        "realm_access": {"roles": ["admin"]},
        "iat": 1704067200,
        "exp": 1704153600,
        "iss": "http://keycloak.celine.localhost/realms/celine",
    }


@pytest.fixture
def sample_service_claims() -> dict:
    """Sample JWT claims for a service account."""
    return {
        "sub": "service-account-celine-cli",
        "client_id": "celine-cli",
        "clientHost": "127.0.0.1",
        "clientAddress": "127.0.0.1",
        "scope": "openid profile email dataset.query",
        "iat": 1704067200,
        "exp": 1704153600,
        "iss": "http://keycloak.celine.localhost/realms/celine",
    }


@pytest.fixture
def sample_service_admin_claims() -> dict:
    """Sample JWT claims for a service account with admin scope."""
    return {
        "sub": "service-account-celine-cli",
        "client_id": "celine-cli",
        "clientHost": "127.0.0.1",
        "clientAddress": "127.0.0.1",
        "scope": "openid profile email dataset.query dataset.admin",
        "iat": 1704067200,
        "exp": 1704153600,
        "iss": "http://keycloak.celine.localhost/realms/celine",
    }
