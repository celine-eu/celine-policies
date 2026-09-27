"""`keycloak sync-users` runs only on a development realm (ADR-0010, requester 2026-09-27).

On a deployed realm members arrive through onboarding, and a community's
organization through the provisioning reconcile. A YAML seed run there is how
accounts nobody signs in with arrived in the first place, so the command refuses
unless ENV names a development environment, with the same guard
`seed-dev-users` uses (`KeycloakSettings.is_production`: unset, a typo or
`staging` is production).

The refusal comes before anything is read or asked: no source is resolved and no
Keycloak client is made, for `--dry-run` and `--check` too. `clean_env` strips
`ENV`, so each test sets exactly the environment it names.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from celine.policies.cli.keycloak.commands import sync_users as sync_users_module
from celine.policies.cli.main import app

runner = CliRunner()

SENTINEL = "source reached"


@pytest.fixture
def reached(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record whether the command got past the guard.

    Resolving the source is the first thing after it; it fails with a sentinel
    here so an allowed run stops without a registry or a Keycloak.
    """
    calls: list[str] = []

    def fake_resolve(*args, **kwargs):
        calls.append("resolve")
        raise sync_users_module._SourceError(SENTINEL)

    monkeypatch.setattr(sync_users_module, "_resolve_source", fake_resolve)
    monkeypatch.setattr(
        sync_users_module,
        "KeycloakAdminClient",
        lambda *a, **k: pytest.fail("reached Keycloak"),
    )
    return calls


@pytest.mark.parametrize("env", [None, "prod", "production", "staging"])
@pytest.mark.parametrize(
    "args",
    [[], ["example-rec.yaml"], ["--dry-run"], ["--check"], ["--from-registry"]],
    ids=["no-args", "file", "dry-run", "check", "registry"],
)
def test_it_refuses_outside_development(monkeypatch, reached, env, args):
    """@verifies REQ-0006"""
    if env:
        monkeypatch.setenv("ENV", env)

    result = runner.invoke(app, ["keycloak", "sync-users", *args])

    assert result.exit_code == 1
    assert "sync-users runs only on a development realm" in result.output
    assert "ENV=dev" in result.output
    assert reached == []


@pytest.mark.parametrize("env", ["dev", "development", "local", "test", "ci"])
def test_it_runs_in_a_development_environment(monkeypatch, reached, env):
    """@verifies REQ-0006"""
    monkeypatch.setenv("ENV", env)

    result = runner.invoke(app, ["keycloak", "sync-users", "--check"])

    assert "development realm" not in result.output
    assert reached == ["resolve"]
    assert SENTINEL in result.output


def test_the_celine_keycloak_env_alias_is_the_same_guard(monkeypatch, reached):
    """The settings' own alias order: `CELINE_KEYCLOAK_ENV` wins over `ENV`."""
    monkeypatch.setenv("ENV", "dev")
    monkeypatch.setenv("CELINE_KEYCLOAK_ENV", "prod")

    result = runner.invoke(app, ["keycloak", "sync-users"])

    assert result.exit_code == 1
    assert reached == []
