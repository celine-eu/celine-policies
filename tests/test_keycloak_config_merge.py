"""One realm, more than one file that declares it.

`sync` recomputes the grants of every client *present* in the file it is given.
A file that describes only part of a realm therefore does not leave the rest
alone — it silently narrows the clients it does mention, with nothing deleted
and no flag involved. That asymmetry (an absent client is an orphan and needs
`--prune`; a *grant* on a client that stays does not) is the whole reason the
loader merges.

Two things are being protected here, and they pull in opposite directions:

* **Nothing about a single file may move.** Every existing invocation passes
  one file, including the deployment containers, so `from_yaml` and a one-file
  `sync` have to behave exactly as they did. The merge of one document is that
  document, and the tests below assert it against the config the pre-merge
  loader produced, not just against an exit code.
* **A partial sync must be impossible to run by accident.** Once a file has
  shed the half another file declares, syncing it alone is the exact failure
  this mechanism exists to prevent — so a file states what it cannot be synced
  without, and the sync refuses when it is missing.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from celine.policies.cli.keycloak.client import CurrentState
from celine.policies.cli.keycloak.models import (
    KeycloakConfig,
    MergeError,
    _resolve_env,
)
from celine.policies.cli.keycloak.sync import SyncResult, compute_sync_plan
from celine.policies.cli.main import app

runner = CliRunner()

CLIENTS_YAML = Path(__file__).resolve().parents[1] / "clients.yaml"


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def _loaded_the_way_it_used_to_be(path: Path) -> KeycloakConfig:
    """The loader exactly as it read before the merge existed.

    Parse, interpolate, validate — no merge, no checks. The reference the
    compatibility assertions below are made against.
    """
    raw = yaml.safe_load(path.read_text())
    return KeycloakConfig.model_validate(_resolve_env(raw))


# ---------------------------------------------------------------------------
# The merge of one document is that document
# ---------------------------------------------------------------------------


class TestOneFileIsUnchanged:
    """The compatibility requirement, asserted against the shipped file."""

    def test_the_shipped_config_is_identical(self):
        assert (
            KeycloakConfig.from_yaml(CLIENTS_YAML).model_dump()
            == _loaded_the_way_it_used_to_be(CLIENTS_YAML).model_dump()
        )

    def test_the_shipped_file_plans_the_same_sync(self):
        """Not 'it exits zero' — the actions themselves have to be identical.

        `compute_sync_plan` against an empty realm is every create, every grant
        and every audience mapper the file implies, so an equal plan is an equal
        declaration.
        """
        before = compute_sync_plan(_loaded_the_way_it_used_to_be(CLIENTS_YAML), CurrentState())
        after = compute_sync_plan(KeycloakConfig.from_yaml(CLIENTS_YAML), CurrentState())

        assert after == before

    def test_the_secret_variables_are_still_recovered(self):
        """`_raw_secrets` is captured from the merged text, so this could move."""
        config = KeycloakConfig.from_yaml(CLIENTS_YAML)

        assert config.secret_source("svc-dataset-api") == "SVC_DATASET_SECRET"
        assert {
            client.client_id: config.secret_source(client.client_id)
            for client in config.clients
        } == {
            client.client_id: config.secret_source(client.client_id)
            for client in KeycloakConfig.from_yaml_files([CLIENTS_YAML]).clients
        }

    def test_one_path_through_the_merging_constructor_is_the_same(self):
        assert (
            KeycloakConfig.from_yaml_files([CLIENTS_YAML]).model_dump()
            == KeycloakConfig.from_yaml(CLIENTS_YAML).model_dump()
        )

    def test_no_paths_at_all_is_refused(self):
        with pytest.raises(ValueError, match="At least one"):
            KeycloakConfig.from_yaml_files([])

    def test_a_missing_file_is_still_reported_as_such(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            KeycloakConfig.from_yaml_files([tmp_path / "nope.yaml"])

    def test_a_non_mapping_document_is_still_rejected(self, tmp_path: Path):
        path = _write(tmp_path, "a.yaml", "- just\n- a\n- list\n")
        with pytest.raises(ValueError, match="must be a YAML mapping"):
            KeycloakConfig.from_yaml_files([path])


# ---------------------------------------------------------------------------
# Grants: any file may widen a client another file declares
# ---------------------------------------------------------------------------


@pytest.fixture
def base(tmp_path: Path) -> Path:
    return _write(
        tmp_path,
        "clients.yaml",
        """
        realm: celine
        scopes:
          - name: dataset.query
            description: Query datasets
        clients:
          - client_id: svc-dataset-api
            name: Dataset API
            scopes_prefix: dataset
            default_scopes: [dataset.query]
        """,
    )


class TestGrants:
    def test_a_second_file_adds_a_grant_without_owning_the_client(
        self, tmp_path: Path, base: Path
    ):
        """The point of the split: a host keeps its grant on a guest's client."""
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            scopes:
              - name: rec-registry.members.write
                description: Write REC members
            clients:
              - client_id: svc-dataset-api
                default_scopes: [rec-registry.members.write]
            """,
        )

        config = KeycloakConfig.from_yaml_files([base, overlay])
        client = config.clients[0]

        assert [c.client_id for c in config.clients] == ["svc-dataset-api"]
        assert client.name == "Dataset API"
        assert client.default_scopes == ["dataset.query", "rec-registry.members.write"]

    def test_the_grant_may_come_before_the_declaration(self, tmp_path: Path):
        """Order is not precedence: the base states a grant, the overlay owns it."""
        first = _write(
            tmp_path,
            "clients.yaml",
            """
            scopes:
              - name: dataset.query
            clients:
              - client_id: svc-ds-onboarding
                default_scopes: [dataset.query]
            """,
        )
        second = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            scopes:
              - name: identity-registry.read
            clients:
              - client_id: svc-ds-onboarding
                name: Onboarding
                scopes_prefix: identity-registry
                default_scopes: [identity-registry.read]
            """,
        )

        client = KeycloakConfig.from_yaml_files([first, second]).clients[0]

        assert client.name == "Onboarding"
        assert client.scopes_prefix == "identity-registry"
        assert client.default_scopes == ["dataset.query", "identity-registry.read"]

    def test_a_grant_both_files_state_appears_once(self, tmp_path: Path, base: Path):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            clients:
              - client_id: svc-dataset-api
                default_scopes: [dataset.query]
            """,
        )

        client = KeycloakConfig.from_yaml_files([base, overlay]).clients[0]

        assert client.default_scopes == ["dataset.query"]

    def test_optional_scopes_and_audiences_merge_too(self, tmp_path: Path, base: Path):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            scopes:
              - name: provenance.read
            clients:
              - client_id: svc-dataset-api
                optional_scopes: [provenance.read]
                extra_audiences: [oauth2_proxy]
            """,
        )

        client = KeycloakConfig.from_yaml_files([base, overlay]).clients[0]

        assert client.optional_scopes == ["provenance.read"]
        assert client.extra_audiences == ["oauth2_proxy"]

    def test_a_client_only_the_second_file_declares_is_added(
        self, tmp_path: Path, base: Path
    ):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            clients:
              - client_id: svc-ds-portal
                name: DS Portal
                scopes_prefix: portal
            """,
        )

        config = KeycloakConfig.from_yaml_files([base, overlay])

        assert config.get_client_ids() == {"svc-dataset-api", "svc-ds-portal"}


# ---------------------------------------------------------------------------
# Identity: exactly one file owns a client
# ---------------------------------------------------------------------------


class TestIdentityHasOneOwner:
    def test_two_files_declaring_one_client_is_refused(
        self, tmp_path: Path, base: Path
    ):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            clients:
              - client_id: svc-dataset-api
                name: Someone Else's Dataset API
            """,
        )

        with pytest.raises(MergeError) as excinfo:
            KeycloakConfig.from_yaml_files([base, overlay])

        message = str(excinfo.value)
        assert "svc-dataset-api" in message
        assert str(base) in message and str(overlay) in message
        assert "name" in message

    @pytest.mark.parametrize(
        "key, value",
        [
            ("secret", "hunter2"),
            ("scopes_prefix", "dataset"),
            ("service_account_enabled", "false"),
            ("description", "anything"),
        ],
    )
    def test_every_identity_key_is_owned(
        self, tmp_path: Path, base: Path, key: str, value: str
    ):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            f"""
            clients:
              - client_id: svc-dataset-api
                {key}: {value}
            """,
        )

        with pytest.raises(MergeError, match=key):
            KeycloakConfig.from_yaml_files([base, overlay])

    def test_one_file_declaring_a_client_twice_is_refused(self, tmp_path: Path):
        path = _write(
            tmp_path,
            "clients.yaml",
            """
            clients:
              - client_id: svc-dataset-api
                name: First
              - client_id: svc-dataset-api
                name: Second
            """,
        )

        with pytest.raises(MergeError, match="twice"):
            KeycloakConfig.from_yaml_files([path])

    def test_a_grant_on_a_client_nobody_declares_is_refused(self, tmp_path: Path):
        """Otherwise the sync creates a client with no name and a generated secret.

        This is what a forgotten file looks like from the inside. It is a
        completeness question rather than a merge one — the entry contradicts
        nothing, it just has no owner among the files supplied.
        """
        path = _write(
            tmp_path,
            "clients.yaml",
            """
            scopes:
              - name: dataset.query
            clients:
              - client_id: svc-ghost
                default_scopes: [dataset.query]
            """,
        )

        with pytest.raises(MergeError, match="svc-ghost"):
            KeycloakConfig.from_yaml_files([path])

    def test_the_owner_may_be_in_any_supplied_file(self, tmp_path: Path, base: Path):
        """Which is why it is checked over the set, not per file."""
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            clients:
              - client_id: svc-ds-portal
                name: DS Portal
            """,
        )
        granting = _write(
            tmp_path,
            "clients.grants.yaml",
            """
            clients:
              - client_id: svc-ds-portal
                default_scopes: [dataset.query]
            """,
        )

        config = KeycloakConfig.from_yaml_files([granting, base, overlay])

        assert config.get_client_ids() == {"svc-dataset-api", "svc-ds-portal"}

    def test_a_client_entry_without_a_client_id_is_refused(self, tmp_path: Path):
        path = _write(tmp_path, "clients.yaml", "clients:\n  - name: nameless\n")

        with pytest.raises(MergeError, match="client_id"):
            KeycloakConfig.from_yaml_files([path])


# ---------------------------------------------------------------------------
# Scopes: once, or identically more than once
# ---------------------------------------------------------------------------


class TestScopeDeclaration:
    def test_an_identical_redeclaration_is_accepted(self, tmp_path: Path, base: Path):
        """The deliberate deviation from ds's merge, which refuses any repeat.

        The two files that will be merged in practice declare many of the same
        scopes today. Refusing outright would make the split a flag-day cut;
        allowing an identical repeat lets the base file shed its copies one
        release at a time.
        """
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            scopes:
              - name: dataset.query
                description: Query datasets
            clients:
              - client_id: svc-ds-portal
                name: DS Portal
                default_scopes: [dataset.query]
            """,
        )

        config = KeycloakConfig.from_yaml_files([base, overlay])

        assert [s.name for s in config.scopes] == ["dataset.query"]

    def test_a_conflicting_redeclaration_is_refused(self, tmp_path: Path, base: Path):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            scopes:
              - name: dataset.query
                description: Something else entirely
            """,
        )

        with pytest.raises(MergeError) as excinfo:
            KeycloakConfig.from_yaml_files([base, overlay])

        message = str(excinfo.value)
        assert "dataset.query" in message
        assert str(base) in message and str(overlay) in message

    def test_scopes_from_both_files_are_present(self, tmp_path: Path, base: Path):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            scopes:
              - name: identity-registry.read
            clients:
              - client_id: svc-ds-portal
                name: DS Portal
                default_scopes: [identity-registry.read]
            """,
        )

        config = KeycloakConfig.from_yaml_files([base, overlay])

        assert config.get_scope_names() == {"dataset.query", "identity-registry.read"}

    def test_a_scope_entry_without_a_name_is_refused(self, tmp_path: Path):
        path = _write(tmp_path, "clients.yaml", "scopes:\n  - description: no name\n")

        with pytest.raises(MergeError, match="no name"):
            KeycloakConfig.from_yaml_files([path])


# ---------------------------------------------------------------------------
# Realm-level keys: any file may say it, no two may disagree
# ---------------------------------------------------------------------------


class TestRealmKeys:
    def test_agreeing_is_fine(self, tmp_path: Path, base: Path):
        overlay = _write(tmp_path, "clients.ds.yaml", "realm: celine\n")

        assert KeycloakConfig.from_yaml_files([base, overlay]).realm == "celine"

    def test_disagreeing_is_refused(self, tmp_path: Path, base: Path):
        overlay = _write(tmp_path, "clients.ds.yaml", "realm: dataspace\n")

        with pytest.raises(MergeError) as excinfo:
            KeycloakConfig.from_yaml_files([base, overlay])

        message = str(excinfo.value)
        assert "realm" in message
        assert "celine" in message and "dataspace" in message

    def test_omitting_it_is_normal(self, tmp_path: Path, base: Path):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            clients:
              - client_id: svc-ds-portal
                name: DS Portal
            """,
        )

        assert KeycloakConfig.from_yaml_files([base, overlay]).realm == "celine"

    def test_the_oauth2_proxy_client_may_come_from_either_file(
        self, tmp_path: Path, base: Path
    ):
        overlay = _write(tmp_path, "clients.ds.yaml", "oauth2_proxy_client: oauth2_proxy\n")

        config = KeycloakConfig.from_yaml_files([base, overlay])

        assert config.oauth2_proxy_client == "oauth2_proxy"


# ---------------------------------------------------------------------------
# Two clients may not claim one scopes_prefix
# ---------------------------------------------------------------------------


class TestScopePrefixOwnership:
    """The check that did not exist, because one file never exhibited it.

    `build_prefix_to_client_map` is a dict comprehension: a second claimant
    silently wins and every audience mapper derived from that prefix points at
    the wrong client. Merging two files makes it reachable — and immediately so,
    since a host and a guest can both call a client 'the dataset one'.
    """

    def test_the_shipped_file_has_no_contested_prefix(self):
        assert KeycloakConfig.from_yaml(CLIENTS_YAML).contested_scope_prefixes() == {}

    def test_two_claimants_are_refused(self, tmp_path: Path, base: Path):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            clients:
              - client_id: svc-ds-dataset-api
                name: DS Dataset API
                scopes_prefix: dataset
            """,
        )

        with pytest.raises(MergeError) as excinfo:
            KeycloakConfig.from_yaml_files([base, overlay])

        message = str(excinfo.value)
        assert "dataset" in message
        assert "svc-dataset-api" in message and "svc-ds-dataset-api" in message

    def test_it_is_reported_rather_than_raised_on_a_config_built_in_memory(self):
        """The check is a method, so callers can ask without loading a file."""
        config = KeycloakConfig.model_validate(
            {
                "clients": [
                    {"client_id": "a", "scopes_prefix": "dataset"},
                    {"client_id": "b", "scopes_prefix": "dataset"},
                ]
            }
        )

        assert config.contested_scope_prefixes() == {"dataset": ["a", "b"]}


# ---------------------------------------------------------------------------
# The guards downstream see the merged realm
# ---------------------------------------------------------------------------


class TestGuardsSeeEverything:
    def test_a_secret_declared_in_the_second_file_names_its_variable(
        self, tmp_path: Path, base: Path
    ):
        """`_raw_secrets` is captured from the merged raw text, before resolution.

        It cannot be derived from the client id — `svc-dataset-api` reads
        `SVC_DATASET_SECRET` — so a client arriving from a second file has to
        carry its own mapping through the merge.
        """
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            clients:
              - client_id: svc-ds-portal
                name: DS Portal
                secret: ${DS_PORTAL_SECRET:-svc-ds-portal}
            """,
        )

        config = KeycloakConfig.from_yaml_files([base, overlay])

        assert config.secret_source("svc-ds-portal") == "DS_PORTAL_SECRET"

    def test_the_placeholder_guard_sees_clients_from_every_file(
        self, tmp_path: Path, base: Path
    ):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            clients:
              - client_id: svc-ds-portal
                name: DS Portal
                secret: ${DS_PORTAL_SECRET:-svc-ds-portal}
            """,
        )

        config = KeycloakConfig.from_yaml_files([base, overlay])

        assert config.clients_with_placeholder_secrets() == ["svc-ds-portal"]

    def test_a_grant_is_satisfied_by_a_scope_the_other_file_declares(
        self, tmp_path: Path, base: Path
    ):
        """Checked over the merged realm, so the two halves may live apart."""
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            scopes:
              - name: identity-registry.read
            clients:
              - client_id: svc-ds-portal
                name: DS Portal
                default_scopes: [identity-registry.read]
            """,
        )

        config = KeycloakConfig.from_yaml_files([base, overlay])

        assert config.validate_scope_references() == []

    def test_a_grant_naming_a_scope_no_file_declares_is_reported(
        self, tmp_path: Path, base: Path
    ):
        """The mistake the split makes possible: the grant stayed, the scope moved."""
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            clients:
              - client_id: svc-ds-portal
                name: DS Portal
                default_scopes: [identity-registry.read]
            """,
        )

        config = KeycloakConfig.from_yaml_files([base, overlay])

        assert config.validate_scope_references() == ["identity-registry.read"]


# ---------------------------------------------------------------------------
# A file states what it cannot be synced without
# ---------------------------------------------------------------------------


@pytest.fixture
def dependent(tmp_path: Path) -> Path:
    """A base file that has shed the half another declaration owns."""
    return _write(
        tmp_path,
        "clients.yaml",
        """
        realm: celine
        requires: [ds]
        scopes:
          - name: rec-registry.members.write
        clients:
          - client_id: svc-celine
            name: Celine
            scopes_prefix: rec-registry
          - client_id: svc-ds-onboarding
            default_scopes: [rec-registry.members.write]
        """,
    )


@pytest.fixture
def declaration(tmp_path: Path) -> Path:
    """The file that answers it."""
    return _write(
        tmp_path,
        "clients.ds.yaml",
        """
        overlay: ds
        scopes:
          - name: identity-registry.read
        clients:
          - client_id: svc-ds-onboarding
            name: DS Onboarding
            scopes_prefix: identity-registry
            default_scopes: [identity-registry.read]
        """,
    )


class TestDeclaredDependencies:
    def test_supplying_it_satisfies_the_requirement(
        self, dependent: Path, declaration: Path
    ):
        config = KeycloakConfig.from_yaml_files([dependent, declaration])

        assert config.requires == ["ds"]
        onboarding = {c.client_id: c for c in config.clients}["svc-ds-onboarding"]
        assert onboarding.default_scopes == [
            "rec-registry.members.write",
            "identity-registry.read",
        ]

    def test_a_missing_declaration_is_refused(self, dependent: Path):
        """The trap the split creates: one forgotten argument narrows a realm."""
        with pytest.raises(MergeError) as excinfo:
            KeycloakConfig.from_yaml_files([dependent])

        message = str(excinfo.value)
        assert "ds" in message
        assert "--overlay" in message

    def test_a_wrong_declaration_does_not_satisfy_it(
        self, tmp_path: Path, dependent: Path
    ):
        other = _write(tmp_path, "clients.other.yaml", "overlay: energy\n")

        with pytest.raises(MergeError, match="energy"):
            KeycloakConfig.from_yaml_files([dependent, other])

    def test_matching_is_by_name_not_by_path(self, tmp_path: Path, dependent: Path):
        """A deployment mounts a file wherever it likes, under any name."""
        mounted = _write(
            tmp_path,
            "mounted-somewhere-else.yaml",
            """
            overlay: ds
            clients:
              - client_id: svc-ds-onboarding
                name: DS Onboarding
                scopes_prefix: identity-registry
            """,
        )

        assert KeycloakConfig.from_yaml_files([dependent, mounted]).requires == ["ds"]

    def test_from_yaml_does_not_enforce_it(self, dependent: Path):
        """`sync-orgs` and `sync-users` read client ids out of this file.

        They are not writing a realm, so neither the declaration this file needs
        in order to be *synced* nor the grants-only entry waiting for it is any
        of their business — and enforcing either would break two commands this
        change does not touch, the moment the base file sheds its ds half.
        """
        config = KeycloakConfig.from_yaml(dependent)

        assert config.requires == ["ds"]
        assert "svc-ds-onboarding" in config.get_client_ids()

    def test_from_yaml_files_can_be_asked_not_to_enforce_it_either(
        self, dependent: Path
    ):
        assert KeycloakConfig.from_yaml_files([dependent], complete=False).requires == [
            "ds"
        ]

    def test_the_overlay_key_does_not_survive_into_the_realm(
        self, dependent: Path, declaration: Path
    ):
        """It says which file this is, not anything about the realm."""
        config = KeycloakConfig.from_yaml_files([dependent, declaration])

        assert not hasattr(config, "overlay")


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


@pytest.fixture
def async_sync():
    """Stub the part that talks to Keycloak, so 'did it get that far' is visible."""
    with patch(
        "celine.policies.cli.keycloak.commands.sync._async_sync",
        new=AsyncMock(return_value=SyncResult()),
    ) as stub:
        yield stub


class TestUndefinedScopesAreFatal:
    """It was a yellow warning and the sync proceeded.

    That failed *after* the realm had been rewritten: the scope is never created,
    `apply_sync_plan` cannot resolve the name, and `Scope not found` lands in
    `result.errors` at the end of a run that has already written every client
    before it. With a realm declared by more than one file, a dangling grant
    stops being a typo the author sees and becomes the ordinary consequence of a
    grant staying in one file while its scope moves to the other — so it is
    refused up front, like the placeholder-secret guard, and for the same reason.
    """

    @pytest.fixture
    def dangling(self, tmp_path: Path) -> Path:
        return _write(
            tmp_path,
            "clients.yaml",
            """
            realm: celine
            scopes:
              - name: dataset.query
            clients:
              - client_id: svc-dataset-api
                name: Dataset API
                scopes_prefix: dataset
                default_scopes: [dataset.query, dataset.qeury]
            """,
        )

    def test_it_refuses(self, dangling: Path, async_sync: AsyncMock):
        result = runner.invoke(app, ["keycloak", "sync", str(dangling), "--dry-run"])

        assert result.exit_code == 1

    def test_it_fails_before_contacting_keycloak(
        self, dangling: Path, async_sync: AsyncMock
    ):
        """The whole point: the old failure happened after the realm was written."""
        runner.invoke(app, ["keycloak", "sync", str(dangling), "--dry-run"])

        assert not async_sync.called

    def test_it_names_the_scope_and_who_asked_for_it(
        self, dangling: Path, async_sync: AsyncMock
    ):
        result = runner.invoke(app, ["keycloak", "sync", str(dangling), "--dry-run"])

        assert "dataset.qeury" in result.output
        assert "svc-dataset-api" in result.output

    def test_there_is_no_environment_that_accepts_it(
        self, dangling: Path, async_sync: AsyncMock, monkeypatch: pytest.MonkeyPatch
    ):
        """Unlike the placeholder guard, this is not about the environment.

        A grant naming a scope nobody declares means nothing in any realm, so
        `ENV=dev` does not buy it through.
        """
        monkeypatch.setenv("ENV", "dev")

        result = runner.invoke(app, ["keycloak", "sync", str(dangling), "--dry-run"])

        assert result.exit_code == 1
        assert not async_sync.called

    def test_it_applies_to_a_real_run_too(
        self, dangling: Path, async_sync: AsyncMock
    ):
        result = runner.invoke(app, ["keycloak", "sync", str(dangling)])

        assert result.exit_code == 1
        assert not async_sync.called

    def test_a_grant_the_overlay_declares_is_not_flagged(
        self, tmp_path: Path, base: Path, async_sync: AsyncMock
    ):
        """The check is over the merged realm, which is the point of merging."""
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            scopes:
              - name: identity-registry.read
            clients:
              - client_id: svc-ds-portal
                name: DS Portal
                default_scopes: [identity-registry.read]
            """,
        )

        result = runner.invoke(
            app, ["keycloak", "sync", str(base), "--overlay", str(overlay), "--dry-run"]
        )

        assert result.exit_code == 0
        assert async_sync.called

    def test_a_grant_only_the_missing_file_would_declare_is_caught(
        self, tmp_path: Path, base: Path, async_sync: AsyncMock
    ):
        """Forgetting the overlay is now two refusals, and this is the second.

        A base file that declares no `requires:` gets no help from that guard, so
        this is what stands between a forgotten `--overlay` and a realm whose
        grants were silently skipped.
        """
        _write(
            tmp_path,
            "clients.ds.yaml",
            """
            scopes:
              - name: identity-registry.read
            """,
        )
        granting = _write(
            tmp_path,
            "clients.grants.yaml",
            """
            clients:
              - client_id: svc-dataset-api
                default_scopes: [identity-registry.read]
            """,
        )

        result = runner.invoke(
            app,
            ["keycloak", "sync", str(base), "--overlay", str(granting), "--dry-run"],
        )

        assert result.exit_code == 1
        assert "identity-registry.read" in result.output
        assert not async_sync.called

    def test_builtin_scopes_are_not_flagged(
        self, tmp_path: Path, async_sync: AsyncMock
    ):
        """`openid` and friends are Keycloak's, and no file declares them."""
        path = _write(
            tmp_path,
            "clients.yaml",
            """
            scopes:
              - name: dataset.query
            clients:
              - client_id: svc-dataset-api
                name: Dataset API
                scopes_prefix: dataset
                default_scopes: [dataset.query, openid, profile, email]
            """,
        )

        result = runner.invoke(app, ["keycloak", "sync", str(path), "--dry-run"])

        assert result.exit_code == 0
        assert async_sync.called


class TestSyncCommand:
    def test_one_file_still_syncs(self, base: Path, async_sync: AsyncMock):
        result = runner.invoke(app, ["keycloak", "sync", str(base), "--dry-run"])

        assert result.exit_code == 0
        assert async_sync.called

    def test_overlay_is_repeatable(self, tmp_path: Path, base: Path, async_sync: AsyncMock):
        first = _write(
            tmp_path,
            "clients.ds.yaml",
            """
            clients:
              - client_id: svc-ds-portal
                name: DS Portal
            """,
        )
        second = _write(
            tmp_path,
            "clients.energy.yaml",
            """
            clients:
              - client_id: svc-rec
                name: REC Registry
            """,
        )

        result = runner.invoke(
            app,
            [
                "keycloak",
                "sync",
                str(base),
                "--overlay",
                str(first),
                "--overlay",
                str(second),
                "--dry-run",
            ],
        )

        assert result.exit_code == 0
        assert "3 clients" in result.output
        assert async_sync.call_args.kwargs["config"].get_client_ids() == {
            "svc-dataset-api",
            "svc-ds-portal",
            "svc-rec",
        }

    def test_the_merged_files_are_named_in_the_output(
        self, tmp_path: Path, base: Path, async_sync: AsyncMock
    ):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            "clients:\n  - client_id: svc-ds-portal\n    name: DS Portal\n",
        )

        result = runner.invoke(
            app, ["keycloak", "sync", str(base), "--overlay", str(overlay), "--dry-run"]
        )

        assert "Merged 2 files" in result.output
        assert str(overlay) in result.output

    def test_a_conflict_stops_before_keycloak(
        self, tmp_path: Path, base: Path, async_sync: AsyncMock
    ):
        overlay = _write(
            tmp_path,
            "clients.ds.yaml",
            "clients:\n  - client_id: svc-dataset-api\n    name: Not Yours\n",
        )

        result = runner.invoke(
            app, ["keycloak", "sync", str(base), "--overlay", str(overlay), "--dry-run"]
        )

        assert result.exit_code == 1
        assert "svc-dataset-api" in result.output
        assert not async_sync.called

    def test_a_missing_declaration_stops_before_keycloak(
        self, dependent: Path, async_sync: AsyncMock
    ):
        result = runner.invoke(app, ["keycloak", "sync", str(dependent), "--dry-run"])

        assert result.exit_code == 1
        assert not async_sync.called

    def test_an_overlay_that_is_not_on_disk_is_rejected(
        self, tmp_path: Path, base: Path, async_sync: AsyncMock
    ):
        result = runner.invoke(
            app,
            [
                "keycloak",
                "sync",
                str(base),
                "--overlay",
                str(tmp_path / "nope.yaml"),
                "--dry-run",
            ],
        )

        assert result.exit_code != 0
        assert not async_sync.called
