"""REQ-0020: `sync` records client secrets on disk only when asked, owner-only.

Outside dev an unasked run writes nothing; `--secrets-file` or
`CELINE_KEYCLOAK_SECRETS_FILE` asks, and the file is created 0600.
"""

from __future__ import annotations

import stat
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from celine.policies.cli.keycloak.secrets_file import merge_secrets_file
from celine.policies.cli.keycloak.sync import SyncResult
from celine.policies.cli.main import app

runner = CliRunner()

DEFAULT_NAME = ".client.secrets.yaml"


@pytest.fixture
def declaration(tmp_path: Path) -> Path:
    path = tmp_path / "clients.yaml"
    path.write_text(
        textwrap.dedent(
            """
            realm: celine
            clients:
              - client_id: svc-example
                name: Example
                secret: a-deployment-supplied-secret
            """
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    return cwd


@pytest.fixture
def applied():
    """A run that applied one client's secret, without a Keycloak."""
    result = SyncResult(
        clients_created=["svc-example"],
        client_secrets={"svc-example": "a-deployment-supplied-secret"},
    )
    with patch(
        "celine.policies.cli.keycloak.commands.sync._async_sync",
        new=AsyncMock(return_value=result),
    ) as stub:
        yield stub


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_a_default_run_outside_dev_writes_no_file(
    declaration: Path, workdir: Path, applied: AsyncMock
):
    """@verifies REQ-0020"""
    result = runner.invoke(app, ["keycloak", "sync", str(declaration)])

    assert result.exit_code == 0, result.output
    assert applied.called
    assert not (workdir / DEFAULT_NAME).exists()
    assert list(workdir.iterdir()) == []
    assert "not written to disk" in result.output


def test_the_flag_writes_the_named_file_0600(
    declaration: Path, workdir: Path, tmp_path: Path, applied: AsyncMock
):
    """@verifies REQ-0020"""
    target = tmp_path / "out" / "secrets.yaml"
    target.parent.mkdir()

    result = runner.invoke(
        app, ["keycloak", "sync", str(declaration), "--secrets-file", str(target)]
    )

    assert result.exit_code == 0, result.output
    assert _mode(target) == 0o600
    assert "a-deployment-supplied-secret" in target.read_text()
    assert not (workdir / DEFAULT_NAME).exists()


def test_the_variable_writes_the_named_file_0600(
    declaration: Path,
    workdir: Path,
    tmp_path: Path,
    applied: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
):
    """@verifies REQ-0020"""
    target = tmp_path / "from-env.yaml"
    monkeypatch.setenv("CELINE_KEYCLOAK_SECRETS_FILE", str(target))

    result = runner.invoke(app, ["keycloak", "sync", str(declaration)])

    assert result.exit_code == 0, result.output
    assert _mode(target) == 0o600
    assert not (workdir / DEFAULT_NAME).exists()


def test_dev_writes_the_default_file_0600(
    declaration: Path,
    workdir: Path,
    applied: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
):
    """@verifies REQ-0020"""
    monkeypatch.setenv("ENV", "dev")

    result = runner.invoke(app, ["keycloak", "sync", str(declaration)])

    assert result.exit_code == 0, result.output
    assert _mode(workdir / DEFAULT_NAME) == 0o600


def test_a_dry_run_writes_nothing_even_when_asked(
    declaration: Path, tmp_path: Path, applied: AsyncMock
):
    """@verifies REQ-0020"""
    target = tmp_path / "secrets.yaml"

    runner.invoke(
        app,
        ["keycloak", "sync", str(declaration), "--dry-run", "--secrets-file", str(target)],
    )

    assert not target.exists()


def test_an_existing_wider_file_is_narrowed_to_0600(tmp_path: Path):
    """The writer both commands share; a file left 0644 by an older run.

    @verifies REQ-0020
    """
    path = tmp_path / DEFAULT_NAME
    path.write_text("realm: celine\nclients: {}\n")
    path.chmod(0o644)

    merge_secrets_file(path, "celine", {"svc-example": {"secret": "s"}})

    assert _mode(path) == 0o600
