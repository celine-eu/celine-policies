"""`clients.warehouse.yaml`: the realm of the pipeline operators.

The pipelines' environment has a realm of its own, whose only users are the platform
admins signing in to the operator UIs (Prefect, Marquez) through oauth2-proxy. It is a
second *base* declaration, not an overlay on `clients.yaml`: syncing `clients.yaml` there
would create every service client of the platform with nothing behind it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from celine.policies.cli.keycloak.models import KeycloakConfig

REPO_ROOT = Path(__file__).resolve().parents[1]
WAREHOUSE_YAML = REPO_ROOT / "clients.warehouse.yaml"
CLIENTS_YAML = REPO_ROOT / "clients.yaml"


@pytest.fixture
def config(monkeypatch: pytest.MonkeyPatch) -> KeycloakConfig:
    monkeypatch.setenv("CELINE_DOMAIN", "example.org")
    monkeypatch.setenv("CELINE_URL_SCHEME", "https")
    monkeypatch.setenv("OAUTH2_PROXY_CLIENT_SECRET", "a-real-secret")
    return KeycloakConfig.from_yaml_files([WAREHOUSE_YAML])


def test_it_declares_the_browser_login_and_nothing_else(config: KeycloakConfig):
    assert [c.client_id for c in config.clients] == ["oauth2_proxy"]
    assert config.scopes == []
    assert config.oauth2_proxy_client == "oauth2_proxy"


def test_the_operator_uis_are_its_redirects(config: KeycloakConfig):
    proxy = config.clients[0]
    assert proxy.browser is not None
    assert sorted(proxy.browser.redirect_uris) == [
        "https://marquez.example.org/*",
        "https://prefect.example.org/*",
    ]


def test_its_tokens_carry_the_realm_roles(config: KeycloakConfig):
    """`platform-admin` reaches the token in realm_access.roles, through `roles`
    (required of every browser client); the gates admit `role:platform-admin`."""
    proxy = config.clients[0]
    assert "roles" in proxy.default_scopes
    assert proxy.service_account_enabled is False


def test_it_grants_no_service_scope(config: KeycloakConfig):
    """No service runs in this realm: the REC Manager scopes of `clients.yaml` stay out."""
    proxy = config.clients[0]
    assert not [s for s in proxy.default_scopes + proxy.optional_scopes if "." in s]


def test_the_secret_comes_from_the_deployment(config: KeycloakConfig):
    assert config.clients[0].secret == "a-real-secret"


def test_unset_the_secret_is_a_placeholder(monkeypatch: pytest.MonkeyPatch):
    """The production guard catches it, as for `clients.yaml`."""
    monkeypatch.delenv("OAUTH2_PROXY_CLIENT_SECRET", raising=False)
    config = KeycloakConfig.from_yaml_files([WAREHOUSE_YAML])
    assert config.clients[0].has_placeholder_secret()


def test_the_login_settings_match_the_platform_realm(config: KeycloakConfig):
    """Same browser client as in `clients.yaml`, only the hosts and the service scopes differ."""
    platform = next(c for c in KeycloakConfig.from_yaml(CLIENTS_YAML).clients
                    if c.client_id == "oauth2_proxy")
    proxy = config.clients[0]
    for field in ("implicit_flow", "direct_access_grants", "access_token_lifespan",
                  "web_origins"):
        assert getattr(proxy.browser, field) == getattr(platform.browser, field), field
    assert [s for s in platform.default_scopes if "." not in s] == proxy.default_scopes


def test_the_image_ships_it():
    dockerfile = (REPO_ROOT / "Dockerfile").read_text()
    assert "COPY ./clients.warehouse.yaml /app" in dockerfile
