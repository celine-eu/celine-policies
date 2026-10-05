"""REQ-0020: `bootstrap` records the admin CLI client's secret on disk only when asked.

The same rule as `sync`: `--secrets-file` or `CELINE_KEYCLOAK_SECRETS_FILE` asks, `ENV=dev`
writes `.client.secrets.yaml` unasked, any other environment writes nothing and says where
the secret can be read instead. The file is created 0600.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest
from test_platform_declaration import PLATFORM_YAML
from typer.testing import CliRunner

import celine.policies.cli.keycloak.commands.bootstrap as bootstrap_module
from celine.policies.cli.keycloak.platform import PlatformResult
from celine.policies.cli.main import app

runner = CliRunner()

DEFAULT_NAME = ".client.secrets.yaml"
ADMIN_SECRET = "the-generated-admin-cli-secret"


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("CELINE_KEYCLOAK_SECRETS_FILE", raising=False)
    return cwd


@pytest.fixture
def created(monkeypatch: pytest.MonkeyPatch) -> dict:
    """A run through master that created the admin CLI client, without a Keycloak."""
    seen: dict = {}

    async def fake(**kwargs):
        seen.update(kwargs)
        return PlatformResult(), (ADMIN_SECRET, True)

    monkeypatch.setattr(bootstrap_module, "_async_bootstrap", fake)
    monkeypatch.setenv("CELINE_KEYCLOAK_BOOTSTRAP_CLIENT_SECRET", "b" * 40)
    return seen


def _invoke(*extra: str):
    return runner.invoke(
        app, ["keycloak", "bootstrap", str(PLATFORM_YAML), "-u", "http://kc", *extra]
    )


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_a_default_run_outside_dev_writes_no_file(workdir: Path, created: dict):
    """@verifies REQ-0020"""
    result = _invoke()

    assert result.exit_code == 0, result.output
    assert created
    assert list(workdir.iterdir()) == []
    assert ADMIN_SECRET not in result.output
    assert "not written" in result.output
    # Says where the secret is instead.
    assert "Clients > celine-admin-cli > Credentials" in result.output


def test_the_flag_writes_the_named_file_0600(
    workdir: Path, tmp_path: Path, created: dict
):
    """@verifies REQ-0020"""
    target = tmp_path / "out" / "secrets.yaml"
    target.parent.mkdir()

    result = _invoke("--secrets-file", str(target))

    assert result.exit_code == 0, result.output
    assert _mode(target) == 0o600
    assert ADMIN_SECRET in target.read_text()
    assert ADMIN_SECRET not in result.output
    assert not (workdir / DEFAULT_NAME).exists()


def test_the_variable_writes_the_named_file_0600(
    workdir: Path, tmp_path: Path, created: dict, monkeypatch: pytest.MonkeyPatch
):
    """@verifies REQ-0020"""
    target = tmp_path / "from-env.yaml"
    monkeypatch.setenv("CELINE_KEYCLOAK_SECRETS_FILE", str(target))

    result = _invoke()

    assert result.exit_code == 0, result.output
    assert _mode(target) == 0o600
    assert ADMIN_SECRET in target.read_text()
    assert not (workdir / DEFAULT_NAME).exists()


def test_dev_writes_the_default_file_0600(
    workdir: Path, created: dict, monkeypatch: pytest.MonkeyPatch
):
    """@verifies REQ-0020"""
    monkeypatch.setenv("ENV", "dev")

    result = _invoke()

    assert result.exit_code == 0, result.output
    assert _mode(workdir / DEFAULT_NAME) == 0o600
    assert ADMIN_SECRET in (workdir / DEFAULT_NAME).read_text()


def test_a_dry_run_writes_nothing_even_when_asked(
    workdir: Path, tmp_path: Path, created: dict
):
    """@verifies REQ-0020"""
    target = tmp_path / "secrets.yaml"

    result = _invoke("--dry-run", "--secrets-file", str(target))

    assert result.exit_code == 0, result.output
    assert not target.exists()
    assert list(workdir.iterdir()) == []
