"""`clients.yaml` as a data model: env interpolation and audience derivation.

Two things here decide whether cross-service calls work at all.

`_resolve_env` puts client secrets into the config from the environment. A
placeholder that survived unresolved becomes the literal secret Keycloak is
configured with, and every client-credentials login fails afterwards with
nothing pointing at the YAML.

`desired_audiences` decides which `aud-mapper-*` protocol mappers `sync` puts on
a client. Too few and a caller's token is rejected by the service it calls; too
many and a token carries audiences it has no business asserting. It is derived
from scope *names*, so it is silently sensitive to how they are spelled.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from celine.policies.cli.keycloak.models import (
    ClientConfig,
    KeycloakConfig,
    ScopeConfig,
    _resolve_env,
)


def _write(tmp_path: Path, body: str, name: str = "clients.yaml") -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Environment interpolation
# ---------------------------------------------------------------------------


class TestEnvInterpolation:
    def test_a_set_variable_is_substituted(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("SVC_SECRET", "s3cret")
        assert _resolve_env("${SVC_SECRET}") == "s3cret"

    def test_a_default_is_used_when_unset(self):
        assert _resolve_env("${NOT_SET_ANYWHERE:-fallback}") == "fallback"

    def test_a_default_is_used_when_set_but_empty(self, monkeypatch: pytest.MonkeyPatch):
        """An exported-but-empty var is the usual shape of a missing `.env` line.

        Treating it as "set" would configure Keycloak with an empty secret.
        """
        monkeypatch.setenv("SVC_SECRET", "")
        assert _resolve_env("${SVC_SECRET:-fallback}") == "fallback"

    def test_a_variable_with_no_value_and_no_default_becomes_empty(self):
        """Empty, not the literal `${VAR}` — a placeholder must never be a secret."""
        assert _resolve_env("${NOT_SET_ANYWHERE}") == ""

    def test_surrounding_text_is_preserved(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("HOST", "kc.internal")
        assert _resolve_env("https://${HOST}/realms/celine") == "https://kc.internal/realms/celine"

    def test_several_placeholders_in_one_string(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("A", "1")
        monkeypatch.setenv("B", "2")
        assert _resolve_env("${A}-${B}") == "1-2"

    def test_resolution_reaches_into_lists_and_nested_dicts(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Secrets sit inside `clients:` list entries, not at the top level."""
        monkeypatch.setenv("S", "resolved")
        raw = {"clients": [{"secret": "${S}", "scopes": ["${S}", "plain"]}]}
        assert _resolve_env(raw) == {
            "clients": [{"secret": "resolved", "scopes": ["resolved", "plain"]}]
        }

    def test_non_strings_pass_through_untouched(self):
        assert _resolve_env({"n": 1, "b": True, "z": None}) == {"n": 1, "b": True, "z": None}

    def test_a_string_without_placeholders_is_unchanged(self):
        assert _resolve_env("svc-dataset-api") == "svc-dataset-api"

    def test_it_terminates_on_self_referential_values(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Resolution repeats until stable; a value that re-expands must not hang."""
        monkeypatch.setenv("LOOP", "${LOOP}")
        assert _resolve_env("${LOOP}") == "${LOOP}"


# ---------------------------------------------------------------------------
# from_yaml
# ---------------------------------------------------------------------------


class TestFromYaml:
    def test_it_loads_scopes_and_clients(self, tmp_path: Path):
        path = _write(
            tmp_path,
            """
            realm: celine
            scopes:
              - name: dataset.query
                description: Query datasets
            clients:
              - client_id: svc-dataset-api
                scopes_prefix: dataset
                default_scopes: [dataset.query]
            """,
        )
        config = KeycloakConfig.from_yaml(path)

        assert config.realm == "celine"
        assert config.get_scope_names() == {"dataset.query"}
        assert config.get_client_ids() == {"svc-dataset-api"}

    def test_secrets_are_interpolated_on_load(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("SVC_X_SECRET", "from-env")
        path = _write(
            tmp_path,
            """
            clients:
              - client_id: svc-x
                secret: ${SVC_X_SECRET}
              - client_id: svc-y
                secret: ${SVC_Y_SECRET:-dev-default}
            """,
        )
        clients = {c.client_id: c for c in KeycloakConfig.from_yaml(path).clients}

        assert clients["svc-x"].secret == "from-env"
        assert clients["svc-y"].secret == "dev-default"

    def test_a_missing_file_is_reported_as_such(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            KeycloakConfig.from_yaml(tmp_path / "nope.yaml")

    def test_a_non_mapping_document_is_rejected(self, tmp_path: Path):
        """A YAML list would otherwise reach pydantic as a confusing error."""
        path = _write(tmp_path, "- just\n- a\n- list\n")
        with pytest.raises(ValueError, match="must be a YAML mapping"):
            KeycloakConfig.from_yaml(path)

    def test_the_realm_defaults_to_celine(self, tmp_path: Path):
        assert KeycloakConfig.from_yaml(_write(tmp_path, "clients: []\n")).realm == "celine"


# ---------------------------------------------------------------------------
# ClientConfig
# ---------------------------------------------------------------------------


class TestClientConfigDefaults:
    def test_an_omitted_name_stays_empty(self):
        """Documents a gap: the `client_id` fallback never fires.

        `default_name_from_client_id` is a `mode="before"` field validator, and
        pydantic does not run those for a field that was not supplied — so the
        documented fallback is unreachable and the name is simply blank.

        Harmless today: every client in `clients.yaml` sets `name`, and
        `_client_needs_update` skips the comparison when `config.name` is falsy,
        so no spurious update is planned either. Pinned here so that whoever
        repairs the validator sees this expectation flip rather than discovering
        it as a wave of client updates on the next sync.
        """
        assert ClientConfig(client_id="svc-x").name == ""

    def test_an_explicit_name_is_kept(self):
        assert ClientConfig(client_id="svc-x", name="Service X").name == "Service X"

    def test_service_accounts_are_on_by_default(self):
        """Every client this CLI manages authenticates as itself unless told not to."""
        assert ClientConfig(client_id="svc-x").service_account_enabled is True


class TestForeignScopePrefixes:
    def test_a_clients_own_scopes_are_not_foreign(self):
        client = ClientConfig(
            client_id="svc-dataset-api",
            scopes_prefix="dataset",
            default_scopes=["dataset.query", "dataset.admin"],
        )
        assert client.foreign_scope_prefixes() == set()

    def test_scopes_of_another_service_are_foreign(self):
        client = ClientConfig(
            client_id="svc-forecast",
            scopes_prefix="forecast",
            default_scopes=["forecast.admin", "dataset.query"],
        )
        assert client.foreign_scope_prefixes() == {"dataset"}

    def test_optional_scopes_count_too(self):
        """A scope requested on demand still needs the audience in the token."""
        client = ClientConfig(
            client_id="svc-forecast",
            scopes_prefix="forecast",
            optional_scopes=["digital-twin.values.read"],
        )
        assert client.foreign_scope_prefixes() == {"digital-twin"}

    def test_a_client_without_a_prefix_derives_nothing(self):
        """Sudo clients hold scopes from everywhere; deriving would mean *all*.

        They declare `extra_audiences` explicitly instead.
        """
        client = ClientConfig(
            client_id="celine-cli",
            default_scopes=["dataset.admin", "nudging.admin", "onboarding.admin"],
        )
        assert client.foreign_scope_prefixes() == set()

    def test_the_prefix_is_the_text_before_the_first_dot(self):
        client = ClientConfig(
            client_id="svc-x",
            scopes_prefix="x",
            default_scopes=["digital-twin.simulation.values.read"],
        )
        assert client.foreign_scope_prefixes() == {"digital-twin"}


class TestDesiredAudiences:
    PREFIX_MAP = {
        "dataset": "svc-dataset-api",
        "digital-twin": "svc-digital-twin",
        "forecast": "svc-forecast",
    }

    def test_derived_and_explicit_audiences_are_merged(self):
        client = ClientConfig(
            client_id="svc-forecast",
            scopes_prefix="forecast",
            default_scopes=["forecast.admin", "dataset.query"],
            extra_audiences=["oauth2_proxy"],
        )
        assert client.desired_audiences(self.PREFIX_MAP) == {
            "svc-dataset-api",
            "oauth2_proxy",
        }

    def test_a_prefix_nobody_owns_yields_no_audience(self):
        """A typo'd or external scope must not invent a mapper target.

        `sync` warns about it; the mapper is simply not created.
        """
        client = ClientConfig(
            client_id="svc-forecast",
            scopes_prefix="forecast",
            default_scopes=["typo.query"],
        )
        assert client.desired_audiences(self.PREFIX_MAP) == set()

    def test_a_sudo_client_gets_exactly_what_it_declares(self):
        client = ClientConfig(
            client_id="celine-cli",
            default_scopes=["dataset.admin", "digital-twin.admin"],
            extra_audiences=["svc-dataset-api"],
        )
        assert client.desired_audiences(self.PREFIX_MAP) == {"svc-dataset-api"}

    def test_a_self_owned_scope_never_becomes_an_audience(self):
        """A token asserting itself as its own audience is meaningless."""
        client = ClientConfig(
            client_id="svc-dataset-api",
            scopes_prefix="dataset",
            default_scopes=["dataset.query", "dataset.admin"],
        )
        assert client.desired_audiences(self.PREFIX_MAP) == set()

    def test_a_client_needing_nothing_gets_nothing(self):
        assert ClientConfig(client_id="svc-x").desired_audiences(self.PREFIX_MAP) == set()


# ---------------------------------------------------------------------------
# KeycloakConfig helpers
# ---------------------------------------------------------------------------


class TestConfigHelpers:
    @pytest.fixture
    def config(self) -> KeycloakConfig:
        return KeycloakConfig(
            scopes=[
                ScopeConfig(name="dataset.query"),
                ScopeConfig(name="forecast.admin"),
            ],
            clients=[
                ClientConfig(
                    client_id="svc-dataset-api",
                    scopes_prefix="dataset",
                    default_scopes=["dataset.query"],
                ),
                ClientConfig(
                    client_id="svc-forecast",
                    scopes_prefix="forecast",
                    default_scopes=["forecast.admin"],
                    optional_scopes=["dataset.query"],
                ),
                ClientConfig(client_id="celine-cli", default_scopes=["dataset.query"]),
            ],
        )

    def test_referenced_scopes_span_default_and_optional(self, config: KeycloakConfig):
        assert config.get_all_referenced_scopes() == {"dataset.query", "forecast.admin"}

    def test_service_clients_are_the_ones_owning_a_prefix(self, config: KeycloakConfig):
        """These are exactly the clients that validate `aud` on inbound tokens.

        `oauth2_proxy` needs one mapper per entry, so a client missing from here
        rejects every browser token.
        """
        assert config.get_service_client_ids() == {"svc-dataset-api", "svc-forecast"}

    def test_the_prefix_map_points_at_owners_only(self, config: KeycloakConfig):
        assert config.build_prefix_to_client_map() == {
            "dataset": "svc-dataset-api",
            "forecast": "svc-forecast",
        }

    def test_scope_references_all_resolve(self, config: KeycloakConfig):
        assert config.validate_scope_references() == []

    def test_an_undefined_scope_is_reported(self):
        """The failure this catches is a 404 at sync time, or a silent no-op."""
        config = KeycloakConfig(
            scopes=[ScopeConfig(name="dataset.query")],
            clients=[ClientConfig(client_id="svc-x", default_scopes=["dataset.qeury"])],
        )
        assert config.validate_scope_references() == ["dataset.qeury"]

    def test_builtin_keycloak_scopes_need_no_declaration(self):
        """`openid`, `profile`, … exist in every realm and are not ours to create."""
        config = KeycloakConfig(
            clients=[
                ClientConfig(
                    client_id="svc-x",
                    default_scopes=["openid", "profile", "email", "roles"],
                    optional_scopes=["offline_access", "acr", "web-origins"],
                )
            ]
        )
        assert config.validate_scope_references() == []

    def test_undefined_scopes_come_back_sorted(self):
        config = KeycloakConfig(
            clients=[ClientConfig(client_id="svc-x", default_scopes=["z.a", "a.z"])]
        )
        assert config.validate_scope_references() == ["a.z", "z.a"]


# ---------------------------------------------------------------------------
# The real clients.yaml
# ---------------------------------------------------------------------------

CLIENTS_YAML = Path(__file__).resolve().parents[1] / "clients.yaml"


class TestShippedClientsYaml:
    """Repo-wide invariants over the file `keycloak sync` actually applies.

    `test_dataspace_scope` and `test_onboarding_scope` assert what specific
    clients look like; these are the properties that must hold for every entry,
    so a newly added client cannot quietly break the audience wiring.
    """

    @pytest.fixture
    def config(self) -> KeycloakConfig:
        return KeycloakConfig.from_yaml(CLIENTS_YAML)

    def test_every_referenced_scope_is_defined(self, config: KeycloakConfig):
        assert config.validate_scope_references() == []

    def test_client_ids_are_unique(self, config: KeycloakConfig):
        """A duplicate makes the later entry silently win the sync."""
        ids = [c.client_id for c in config.clients]
        assert len(ids) == len(set(ids)), "duplicate client_id in clients.yaml"

    def test_scope_names_are_unique(self, config: KeycloakConfig):
        names = [s.name for s in config.scopes]
        assert len(names) == len(set(names)), "duplicate scope in clients.yaml"

    def test_no_two_clients_claim_the_same_scope_prefix(self, config: KeycloakConfig):
        """`build_prefix_to_client_map` would drop one, misrouting audiences."""
        prefixes = [c.scopes_prefix for c in config.clients if c.scopes_prefix]
        assert len(prefixes) == len(set(prefixes)), "two clients own one prefix"

    # Families deliberately owned by nothing in this realm. An audience mapper
    # can never be derived for these, so anything referencing them must declare
    # the target in `extra_audiences` instead.
    UNOWNED_SCOPE_FAMILIES = {
        "mqtt",  # consumed by the mqtt_auth service, which is not a KC client
        "provenance",  # owned by svc-ds-provenance, deployed with the dataspace
    }

    def test_scope_families_are_owned_or_knowingly_unowned(self, config: KeycloakConfig):
        """A new unowned family is almost always a missing `scopes_prefix`.

        Without an owner nothing derives an audience mapper, so callers get a
        token the target service rejects — and the only symptom is a 401 from a
        service that was never mentioned in the config.
        """
        owned = set(config.build_prefix_to_client_map())
        unowned = {s.name.split(".")[0] for s in config.scopes} - owned
        assert unowned == self.UNOWNED_SCOPE_FAMILIES, (
            "scope families with no owning client changed — either add "
            f"scopes_prefix to the owning client, or justify it here: {unowned}"
        )

    def test_unowned_families_are_reachable_through_extra_audiences(
        self, config: KeycloakConfig
    ):
        """Whoever holds a `provenance.*` scope must name its audience by hand."""
        holders = [
            c
            for c in config.clients
            if any(s.startswith("provenance.") for s in c.default_scopes)
        ]
        assert holders, "no client holds a provenance scope — is the family dead?"
        for client in holders:
            assert "svc-ds-provenance" in client.extra_audiences, (
                f"{client.client_id} holds a provenance scope but declares no "
                "audience for it — its token will be rejected"
            )

    def test_every_derived_audience_resolves_to_a_declared_client(
        self, config: KeycloakConfig
    ):
        """A mapper pointing at a client that does not exist yields a dead `aud`."""
        prefix_map = config.build_prefix_to_client_map()
        known = config.get_client_ids()
        for client in config.clients:
            derived = {
                prefix_map[p]
                for p in client.foreign_scope_prefixes()
                if p in prefix_map
            }
            assert derived <= known, f"{client.client_id} derives an unknown audience"

    def test_external_audiences_are_the_two_known_ones(self, config: KeycloakConfig):
        """`extra_audiences` may point outside this file — but not by accident.

        A typo'd client_id there is invisible: `sync` logs a warning and creates
        the mapper anyway, so the token carries an audience nobody validates.
        """
        known = config.get_client_ids()
        external = {
            audience
            for client in config.clients
            for audience in client.extra_audiences
            if audience not in known
        }
        assert external == {"oauth2_proxy", "svc-ds-provenance"}

    def test_the_oauth2_proxy_client_is_declared(self, config: KeycloakConfig):
        """Without it, no user JWT carries any service audience."""
        assert config.oauth2_proxy_client

    def test_the_admin_cli_owns_no_scope_family(self, config: KeycloakConfig):
        """`celine-cli` holds scopes from every service.

        Giving it a prefix would make `sync` derive an audience mapper for each,
        which is what `extra_audiences` states deliberately instead.
        """
        cli = next(c for c in config.clients if c.client_id == "celine-cli")
        assert cli.scopes_prefix is None
        assert cli.extra_audiences
