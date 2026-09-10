"""`.client.secrets.yaml` — the store the CLI authenticates from.

`KeycloakSettings.with_auto_secret` reads `celine-admin-cli` out of this file for
any run given no `--admin-user`, and `task keycloak:sync` is written to rely on
that. Two commands write the file, and they used to disagree about what it is:
`bootstrap` merged one client into it, `sync` rewrote it with only the clients
that run happened to touch — so a sync that changed anything deleted the
credential the next sync needed (celine-policies#5).

What is worth holding here is the interaction, not either writer alone: bootstrap
then sync, in that order, is the sequence the taskfile runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from celine.policies.cli.keycloak.commands.bootstrap import _update_secrets_file
from celine.policies.cli.keycloak.secrets_file import (
    merge_secrets_file,
    read_secrets_file,
)
from celine.policies.cli.keycloak.settings import _load_secret_from_file
from celine.policies.cli.keycloak.sync import SyncResult, write_secrets_file


def entry(client_id: str, secret: str) -> dict[str, dict]:
    return {client_id: {"client_id": client_id, "secret": secret, "created": True}}


class TestTheTwoWritersShareTheFile:
    def test_a_sync_keeps_the_secret_bootstrap_wrote(self, tmp_path: Path):
        """The defect, in the order the taskfile runs it.

        Without this, `task keycloak:sync` a second time has no credential to
        authenticate with, and the file looks plausible rather than empty.
        """
        path = tmp_path / ".client.secrets.yaml"
        _update_secrets_file(path, "celine", "celine-admin-cli", "admin-secret", True)

        write_secrets_file(
            path, SyncResult(client_secrets={"svc-community": "s"}), "celine"
        )

        assert _load_secret_from_file(path, "celine-admin-cli") == "admin-secret"
        assert _load_secret_from_file(path, "svc-community") == "s"

    def test_bootstrap_keeps_the_clients_sync_wrote(self, tmp_path: Path):
        """And the other way round — re-bootstrapping is not a reset."""
        path = tmp_path / ".client.secrets.yaml"
        write_secrets_file(
            path, SyncResult(client_secrets={"svc-community": "s"}), "celine"
        )

        _update_secrets_file(path, "celine", "celine-admin-cli", "admin-secret", True)

        assert set(yaml.safe_load(path.read_text())["clients"]) == {
            "svc-community",
            "celine-admin-cli",
        }

    def test_the_file_accumulates_across_partial_syncs(self, tmp_path: Path):
        """`result.client_secrets` holds only what a run created or updated.

        A converged realm plans nothing and writes nothing, so the file has to be
        the union of the runs, or it holds whatever the last non-empty one touched.
        """
        path = tmp_path / ".client.secrets.yaml"
        write_secrets_file(path, SyncResult(client_secrets={"svc-a": "a"}), "celine")
        write_secrets_file(path, SyncResult(client_secrets={"svc-b": "b"}), "celine")
        write_secrets_file(path, SyncResult(), "celine")

        assert set(yaml.safe_load(path.read_text())["clients"]) == {"svc-a", "svc-b"}


class TestARealmChangeReplacesTheStore:
    """One `realm:` key, and the reader looks clients up flat.

    So two realms' credentials are not representable in one file: `svc-x` is a
    different client with a different secret in each. Merging across the change
    would hand the next run a credential from the wrong realm — the failure #4
    is about, one file further along.
    """

    def test_credentials_from_another_realm_are_dropped(self, tmp_path: Path):
        path = tmp_path / ".client.secrets.yaml"
        merge_secrets_file(path, "celine", entry("svc-x", "celine-secret"))

        merge_secrets_file(path, "e2e-throwaway", entry("svc-y", "throwaway-secret"))

        data = yaml.safe_load(path.read_text())
        assert data["realm"] == "e2e-throwaway"
        assert set(data["clients"]) == {"svc-y"}

    def test_it_says_so(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        """Silently losing a credential is how this class of bug survives."""
        path = tmp_path / ".client.secrets.yaml"
        merge_secrets_file(path, "celine", entry("svc-x", "s"))

        with caplog.at_level("WARNING"):
            merge_secrets_file(path, "e2e-throwaway", entry("svc-y", "s"))

        assert "celine" in caplog.text
        assert "e2e-throwaway" in caplog.text

    def test_the_same_realm_is_a_merge(self, tmp_path: Path):
        path = tmp_path / ".client.secrets.yaml"
        merge_secrets_file(path, "celine", entry("svc-x", "s"))
        merge_secrets_file(path, "celine", entry("svc-y", "s"))

        assert set(yaml.safe_load(path.read_text())["clients"]) == {"svc-x", "svc-y"}


class TestFileShape:
    def test_a_file_written_by_the_old_sync_is_readable(self, tmp_path: Path):
        """`sync` wrote the warning as a YAML *key*; `bootstrap` wrote a comment.

        Every existing `.client.secrets.yaml` in a working tree has the key, so
        the merging writer has to read one and converge it rather than leaving
        both shapes in the file forever.
        """
        path = tmp_path / ".client.secrets.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "# WARNING": "This file contains sensitive credentials.",
                    "realm": "celine",
                    "clients": {
                        "celine-admin-cli": {
                            "client_id": "celine-admin-cli",
                            "secret": "admin-secret",
                        }
                    },
                }
            )
        )

        merge_secrets_file(path, "celine", entry("svc-x", "s"))

        data = yaml.safe_load(path.read_text())
        assert "# WARNING" not in data
        assert "DO NOT COMMIT" in path.read_text()
        assert _load_secret_from_file(path, "celine-admin-cli") == "admin-secret"

    def test_an_unreadable_file_is_written_over_rather_than_refused(
        self, tmp_path: Path
    ):
        """The command trying to repair the file must not be the one it stops."""
        path = tmp_path / ".client.secrets.yaml"
        path.write_text("clients: [this is\n  not: valid yaml")

        merge_secrets_file(path, "celine", entry("svc-x", "s"))

        assert _load_secret_from_file(path, "svc-x") == "s"

    def test_a_missing_file_reads_as_empty(self, tmp_path: Path):
        assert read_secrets_file(tmp_path / "absent.yaml") == {}

    def test_the_write_is_dated(self, tmp_path: Path):
        path = tmp_path / ".client.secrets.yaml"
        merge_secrets_file(path, "celine", entry("svc-x", "s"))
        assert yaml.safe_load(path.read_text())["generated_at"]
