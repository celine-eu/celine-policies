"""Reading REC definitions from the live registry rather than from a file.

`sync-users` reconciled a file, so it reconciled whatever snapshot an operator
exported, and anybody `../onboarding` had approved since was invisible to it.
The registry serves the identical artefact — `GET /admin/export` returns the same
bundle YAML the loaders already parse — so the change is only where the bytes
come from.

**What these tests guard is that "only where the bytes come from" stays true.**
The property is that nothing below `_load_communities` can tell which source it
got; the moment the two sources produce different plans, this is two code paths
wearing one name.

No network and no registry: the SDK client is a stub, so what is covered is which
call `sync-users` decides to make and what it does with the answer. That the
registry accepts the call is checked by hand.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from celine.policies.cli.keycloak.commands import sync_users as sync_users_module
from celine.policies.cli.keycloak.commands.sync_users import (
    _load_communities,
    _resolve_source,
    _SourceError,
)
from celine.policies.cli.keycloak.registry import (
    RegistryError,
    fetch_rec_documents,
    issuer_url,
)
from celine.policies.cli.keycloak.settings import KeycloakSettings, SyncUsersSettings
from celine.provisioning.registry import RegistryCommunityNotFound

GREENLAND = """
    community:
      id: greenland
      name: Greenland Energy Community
      operators:
        set-distribuzione:
          name: SET Distribuzione S.p.A.
    members:
      gl-00001:
        name: Mario Rossi
        user_id: gl-00001
        status: active
      20260912-a3f9c2:
        name: Alice Onboarded
        user_id: alice@example.com
        status: active
      gl-00009:
        name: Pending Pat
        user_id: pat@example.com
        status: pending
"""

BLUELAND = """
    community:
      id: blueland
      name: Blueland
    members:
      bl-00001:
        name: Bruno Blu
        user_id: bruno@example.com
        status: active
"""


def _stream(*bodies: str) -> str:
    """What the registry returns: one document, or several separated by `---`."""
    return "---\n".join(textwrap.dedent(b) for b in bodies)


@pytest.fixture
def kc_settings() -> KeycloakSettings:
    return KeycloakSettings(
        env="dev",
        base_url="http://kc.internal",
        realm="celine",
        admin_client_secret="secret",
    )


@pytest.fixture
def stub_registry(monkeypatch: pytest.MonkeyPatch):
    """Install a stub fetcher and record what it was asked for."""

    calls: list[dict] = []

    def install(text: str | None = None, *, raises: Exception | None = None):
        async def fake_fetch(**kwargs):
            calls.append(kwargs)
            if raises is not None:
                raise raises
            return [doc for doc in yaml.safe_load_all(text) if doc]

        monkeypatch.setattr(sync_users_module, "fetch_rec_documents", fake_fetch)
        return calls

    return install


# ---------------------------------------------------------------------------
# The issuer
# ---------------------------------------------------------------------------


class TestIssuerUrl:
    """Discovery is rooted at the realm, and the hostname is load-bearing.

    The SDK appends `/.well-known/openid-configuration`, so this is the realm
    URL rather than the Keycloak base. Getting the *hostname* wrong is the
    expensive one: a token minted at one and presented to a service validating
    against another is a bare 401, with nothing in the message about hostnames.
    """

    def test_it_is_the_realm_url(self):
        assert issuer_url("http://kc.internal", "celine") == (
            "http://kc.internal/realms/celine"
        )

    def test_a_trailing_slash_does_not_double(self):
        assert issuer_url("http://kc.internal/", "celine") == (
            "http://kc.internal/realms/celine"
        )


# ---------------------------------------------------------------------------
# The fetcher
# ---------------------------------------------------------------------------


class TestFetchRecDocuments:
    """The registry's own client does the call; this is what surrounds it."""

    @pytest.mark.asyncio
    async def test_a_multidocument_export_becomes_one_document_per_community(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        captured: dict = {}

        class FakeAdminClient:
            def __init__(self, base_url, **kwargs):
                captured["base_url"] = base_url

            async def export_communities(self, keys):
                captured["keys"] = keys
                return _stream(GREENLAND, BLUELAND)

        _install_sdk(monkeypatch, FakeAdminClient)

        docs = await fetch_rec_documents(
            registry_url="http://registry.internal/",
            issuer="http://kc.internal/realms/celine",
            client_id="celine-cli",
            client_secret="s3cret",
        )

        assert [d["community"]["id"] for d in docs] == ["greenland", "blueland"]
        assert captured["base_url"] == "http://registry.internal"
        assert captured["keys"] is None

    @pytest.mark.asyncio
    async def test_named_communities_are_passed_through(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """`community` is repeatable on the endpoint, so narrowing is the server's."""
        captured: dict = {}

        class FakeAdminClient:
            def __init__(self, base_url, **kwargs):
                pass

            async def export_communities(self, keys):
                captured["keys"] = keys
                return _stream(GREENLAND)

        _install_sdk(monkeypatch, FakeAdminClient)

        await fetch_rec_documents(
            registry_url="http://registry.internal",
            issuer="http://kc.internal/realms/celine",
            client_id="celine-cli",
            client_secret="s3cret",
            community_keys=["greenland"],
        )

        assert captured["keys"] == ["greenland"]

    @pytest.mark.asyncio
    async def test_a_failure_names_the_url_the_client_and_the_issuer(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """"Unauthorized" alone sends an operator to the wrong place.

        The two failures here look identical from the outside and have opposite
        causes: a 401 is an issuer the registry does not validate against, a 403
        is a client without the scope. The message has to carry enough to tell
        them apart.
        """

        class FakeAdminClient:
            def __init__(self, base_url, **kwargs):
                pass

            async def export_communities(self, keys):
                raise RuntimeError("401 Unauthorized")

        _install_sdk(monkeypatch, FakeAdminClient)

        with pytest.raises(RegistryError) as excinfo:
            await fetch_rec_documents(
                registry_url="http://registry.internal",
                issuer="http://kc.internal/realms/celine",
                client_id="celine-cli",
                client_secret="s3cret",
            )

        message = str(excinfo.value)
        assert "http://registry.internal" in message
        assert "celine-cli" in message
        assert "http://kc.internal/realms/celine" in message
        assert "rec-registry.export" in message

    @pytest.mark.asyncio
    async def test_an_empty_export_is_refused_rather_than_reported_as_success(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """A run that provisions nobody must not exit 0 saying nothing.

        An empty registry is the expected state before onboarding has approved
        anybody — which is exactly when somebody would wrongly conclude the
        realm is reconciled.
        """

        class FakeAdminClient:
            def __init__(self, base_url, **kwargs):
                pass

            async def export_communities(self, keys):
                return ""

        _install_sdk(monkeypatch, FakeAdminClient)

        with pytest.raises(RegistryError, match="exported no community"):
            await fetch_rec_documents(
                registry_url="http://registry.internal",
                issuer="http://kc.internal/realms/celine",
                client_id="celine-cli",
                client_secret="s3cret",
            )

    @pytest.mark.asyncio
    async def test_only_the_export_method_is_ever_called(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """The credential is wide; the code's use of it is what keeps it safe.

        `celine-cli` holds `rec-registry.admin`, which also grants `import` — a
        replacement import that deletes a community with every member in it —
        and `members.purge`. Narrowing the *realm* declaration was declined, so
        this is the mitigation that remains: the fetcher touches one read-only
        method and nothing else in this repository names a second.
        """
        touched: list[str] = []

        class FakeAdminClient:
            def __init__(self, base_url, **kwargs):
                pass

            def __getattr__(self, name):
                touched.append(name)
                raise AssertionError(f"sync-users must not call {name}")

            async def export_communities(self, keys):
                return _stream(GREENLAND)

        _install_sdk(monkeypatch, FakeAdminClient)

        await fetch_rec_documents(
            registry_url="http://registry.internal",
            issuer="http://kc.internal/realms/celine",
            client_id="celine-cli",
            client_secret="s3cret",
        )

        assert touched == []


    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "content,keys,unknown_community",
        [
            # the registry's own answer for an unknown key
            (b'{"detail":"\'Community not found: nowhere\'"}', ["nowhere"], True),
            # FastAPI's unrouted path: a wrong registry URL, an outage
            (b'{"detail":"Not Found"}', ["nowhere"], False),
            (b"<html>not found</html>", ["nowhere"], False),
            # an unnarrowed export names no community to be missing
            (b'{"detail":"\'Community not found: nowhere\'"}', None, False),
        ],
        ids=["unknown-community", "unrouted", "not-json", "unnarrowed"],
    )
    async def test_a_404_is_an_unknown_community_only_when_the_registry_says_so(
        self, monkeypatch: pytest.MonkeyPatch, content, keys, unknown_community
    ):
        """The provisioning service answers `community_not_found` on this, and
        `../onboarding` reads a `404` on disable as "nothing left to revoke" —
        so a misconfigured URL must stay an outage."""

        class UnexpectedStatus(Exception):
            def __init__(self, status_code, content):
                super().__init__(f"Unexpected status code: {status_code}")
                self.status_code = status_code
                self.content = content

        class FakeAdminClient:
            def __init__(self, base_url, **kwargs):
                pass

            async def export_communities(self, keys):
                raise UnexpectedStatus(404, content)

        _install_sdk(monkeypatch, FakeAdminClient)

        with pytest.raises(RegistryError) as excinfo:
            await fetch_rec_documents(
                registry_url="http://registry.internal",
                issuer="http://kc.internal/realms/celine",
                client_id="celine-cli",
                client_secret="s3cret",
                community_keys=keys,
            )

        assert isinstance(excinfo.value, RegistryCommunityNotFound) is unknown_community


def _install_sdk(monkeypatch: pytest.MonkeyPatch, admin_client) -> None:
    """Stub the two SDK names `fetch_rec_documents` imports at call time."""
    import sys
    import types

    auth = types.ModuleType("celine.sdk.auth")
    auth.OidcClientCredentialsProvider = lambda **kwargs: object()
    registry = types.ModuleType("celine.sdk.rec_registry")
    registry.RecRegistryAdminClient = admin_client

    monkeypatch.setitem(sys.modules, "celine.sdk.auth", auth)
    monkeypatch.setitem(sys.modules, "celine.sdk.rec_registry", registry)


# ---------------------------------------------------------------------------
# Choosing a source
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, *bodies: str, name: str = "rec.yaml") -> Path:
    path = tmp_path / name
    path.write_text(_stream(*bodies), encoding="utf-8")
    return path


class TestChoosingASource:
    def test_a_file_path_still_works_and_is_not_deprecated(
        self, tmp_path: Path, kc_settings
    ):
        """Bootstrap runs before the registry holds anything, and offline is real."""
        path = _write(tmp_path, GREENLAND)
        settings = SyncUsersSettings(rec_yaml=path)

        documents, source = _resolve_source(
            settings, kc_settings=kc_settings, from_registry=False
        )

        assert [d["community"]["id"] for d in documents] == ["greenland"]
        assert source == str(path)

    def test_both_sources_at_once_is_refused_naming_the_one_it_would_use(
        self, tmp_path: Path, kc_settings
    ):
        """Silently preferring one would make the flag look like it did nothing."""
        settings = SyncUsersSettings(
            rec_yaml=_write(tmp_path, GREENLAND),
            registry_url="http://registry.internal",
        )

        with pytest.raises(_SourceError, match="mutually exclusive"):
            _resolve_source(settings, kc_settings=kc_settings, from_registry=True)

    def test_neither_source_names_both_ways_out(self, kc_settings):
        with pytest.raises(_SourceError) as excinfo:
            _resolve_source(
                SyncUsersSettings(), kc_settings=kc_settings, from_registry=False
            )

        assert "CELINE_SYNC_USERS_REC_YAML" in str(excinfo.value)
        assert "--from-registry" in str(excinfo.value)

    def test_the_registry_needs_a_url(self, kc_settings):
        with pytest.raises(_SourceError, match="--registry-url"):
            _resolve_source(
                SyncUsersSettings(), kc_settings=kc_settings, from_registry=True
            )

    def test_a_missing_file_is_refused_before_anything_is_authenticated(
        self, tmp_path: Path, kc_settings
    ):
        settings = SyncUsersSettings(rec_yaml=tmp_path / "nope.yaml")

        with pytest.raises(_SourceError, match="file not found"):
            _resolve_source(settings, kc_settings=kc_settings, from_registry=False)

    def test_a_registry_url_alone_selects_the_registry(
        self, stub_registry, kc_settings
    ):
        """`CELINE_SYNC_USERS_REGISTRY_URL` should not also need the flag."""
        stub_registry(_stream(GREENLAND))
        settings = SyncUsersSettings(
            registry_url="http://registry.internal",
            registry_client_secret="s3cret",
        )

        documents, source = _resolve_source(
            settings, kc_settings=kc_settings, from_registry=True
        )

        assert [d["community"]["id"] for d in documents] == ["greenland"]
        assert source == "registry http://registry.internal"

    def test_the_registry_call_gets_the_realm_issuer(self, stub_registry, kc_settings):
        calls = stub_registry(_stream(GREENLAND))
        settings = SyncUsersSettings(
            registry_url="http://registry.internal", registry_client_secret="s3cret"
        )

        _resolve_source(settings, kc_settings=kc_settings, from_registry=True)

        assert calls[0]["issuer"] == "http://kc.internal/realms/celine"
        assert calls[0]["client_id"] == "celine-cli"
        assert calls[0]["client_secret"] == "s3cret"

    def test_a_registry_failure_surfaces_as_a_source_error(
        self, stub_registry, kc_settings
    ):
        """The command prints `_SourceError` and exits 1; a bare traceback is not that."""
        stub_registry(raises=RegistryError("could not reach it"))
        settings = SyncUsersSettings(
            registry_url="http://registry.internal", registry_client_secret="s3cret"
        )

        with pytest.raises(_SourceError, match="could not reach it"):
            _resolve_source(settings, kc_settings=kc_settings, from_registry=True)


class TestTheRegistrySecret:
    """Three inputs, least explicit last, and the refusal names all of them."""

    def test_the_explicit_secret_wins(self, tmp_path: Path):
        settings = SyncUsersSettings(registry_client_secret="from-the-flag")
        assert settings.resolve_registry_secret(tmp_path / "none.yaml") == (
            "from-the-flag"
        )

    def test_it_falls_back_to_the_secrets_store(self, tmp_path: Path):
        """`sync` records every client it created there, so it is usually on disk."""
        store = tmp_path / ".client.secrets.yaml"
        store.write_text(
            yaml.safe_dump(
                {"realm": "celine", "clients": {"celine-cli": {"secret": "from-disk"}}}
            )
        )
        settings = SyncUsersSettings()

        assert settings.resolve_registry_secret(store) == "from-disk"

    def test_it_reads_the_entry_for_the_configured_client(self, tmp_path: Path):
        """The client id must stay configurable, so the lookup follows it.

        This is what lets a client holding `rec-registry.export` alone replace
        `celine-cli` without a code change.
        """
        store = tmp_path / ".client.secrets.yaml"
        store.write_text(
            yaml.safe_dump(
                {
                    "realm": "celine",
                    "clients": {
                        "celine-cli": {"secret": "wide"},
                        "svc-policies-sync": {"secret": "narrow"},
                    },
                }
            )
        )
        settings = SyncUsersSettings(registry_client_id="svc-policies-sync")

        assert settings.resolve_registry_secret(store) == "narrow"

    def test_no_secret_anywhere_comes_back_as_none(self, tmp_path: Path):
        """Ordinary, not exceptional: the store holds only clients a run touched."""
        assert SyncUsersSettings().resolve_registry_secret(tmp_path / "none.yaml") is None

    def test_the_refusal_names_all_three_inputs(self, kc_settings, tmp_path: Path):
        settings = SyncUsersSettings(
            registry_url="http://registry.internal"
        ).with_overrides(registry_client_id="celine-cli")
        kc = kc_settings.with_overrides(secrets_file=tmp_path / "none.yaml")

        with pytest.raises(_SourceError) as excinfo:
            _resolve_source(settings, kc_settings=kc, from_registry=True)

        message = str(excinfo.value)
        assert "--registry-client-secret" in message
        assert "CELINE_SYNC_USERS_REGISTRY_CLIENT_SECRET" in message
        assert "none.yaml" in message


# ---------------------------------------------------------------------------
# Narrowing to named communities
# ---------------------------------------------------------------------------


class TestNarrowingToNamedCommunities:
    def test_it_keeps_only_the_named_one(self, tmp_path: Path, kc_settings):
        settings = SyncUsersSettings(
            rec_yaml=_write(tmp_path, GREENLAND, BLUELAND), communities=["blueland"]
        )

        documents, _ = _resolve_source(
            settings, kc_settings=kc_settings, from_registry=False
        )

        assert [d["community"]["id"] for d in documents] == ["blueland"]

    def test_a_name_the_source_does_not_hold_is_refused(
        self, tmp_path: Path, kc_settings
    ):
        """A typo in a scheduled `--community` must not reconcile nothing quietly.

        Reporting success while provisioning nobody makes the run that was
        supposed to catch drift the thing that hides it.
        """
        settings = SyncUsersSettings(
            rec_yaml=_write(tmp_path, GREENLAND), communities=["greenlnad"]
        )

        with pytest.raises(_SourceError, match="greenlnad"):
            _resolve_source(settings, kc_settings=kc_settings, from_registry=False)

    def test_narrowing_the_registry_is_the_servers_job(
        self, stub_registry, kc_settings
    ):
        """Asked for one, the export returns one — and 404s a name it lacks."""
        calls = stub_registry(_stream(GREENLAND))
        settings = SyncUsersSettings(
            registry_url="http://registry.internal",
            registry_client_secret="s3cret",
            communities=["greenland"],
        )

        _resolve_source(settings, kc_settings=kc_settings, from_registry=True)

        assert calls[0]["community_keys"] == ["greenland"]

    def test_naming_nothing_asks_the_registry_for_everything(
        self, stub_registry, kc_settings
    ):
        """The tenant list comes from the registry, in the same artefact.

        That is what makes a scheduled reconcile possible without a list of REC
        slugs maintained somewhere else.
        """
        calls = stub_registry(_stream(GREENLAND, BLUELAND))
        settings = SyncUsersSettings(
            registry_url="http://registry.internal", registry_client_secret="s3cret"
        )

        documents, _ = _resolve_source(
            settings, kc_settings=kc_settings, from_registry=True
        )

        assert calls[0]["community_keys"] is None
        assert [d["community"]["id"] for d in documents] == ["greenland", "blueland"]


# ---------------------------------------------------------------------------
# The seam: one parser, two sources
# ---------------------------------------------------------------------------


class TestTheTwoSourcesProduceTheSamePlans:
    """The claim of the whole change, stated as a test.

    If a file and the registry ever produce different plans from the same bytes,
    this stopped being a source switch and became a second code path.
    """

    def test_a_file_and_an_export_of_the_same_bytes_agree(
        self, tmp_path: Path, stub_registry, kc_settings
    ):
        from_file, _ = _resolve_source(
            SyncUsersSettings(rec_yaml=_write(tmp_path, GREENLAND, BLUELAND)),
            kc_settings=kc_settings,
            from_registry=False,
        )
        stub_registry(_stream(GREENLAND, BLUELAND))
        from_registry, _ = _resolve_source(
            SyncUsersSettings(
                registry_url="http://registry.internal",
                registry_client_secret="s3cret",
            ),
            kc_settings=kc_settings,
            from_registry=True,
        )

        assert _load_communities(from_file, source="file") == _load_communities(
            from_registry, source="registry"
        )


class TestLoadCommunities:
    def test_one_plan_per_document(self):
        plans = _load_communities(
            [doc for doc in yaml.safe_load_all(_stream(GREENLAND, BLUELAND)) if doc],
            source="two.yaml",
        )

        assert [p.community["id"] for p in plans] == ["greenland", "blueland"]
        assert [p.community_type for p in plans] == ["rec", "rec"]

    def test_members_and_operators_travel_with_their_community(self):
        plans = _load_communities(
            [doc for doc in yaml.safe_load_all(_stream(GREENLAND, BLUELAND)) if doc],
            source="two.yaml",
        )

        assert [p["key"] for p in plans[0].participants] == [
            "gl-00001",
            "20260912-a3f9c2",
        ]
        assert [op["id"] for op in plans[0].operators] == ["set-distribuzione"]
        assert plans[1].operators == []

    def test_the_pending_member_is_not_in_any_plan(self):
        """`gl-00009` is `status: pending` and never reaches provisioning."""
        plans = _load_communities(
            [doc for doc in yaml.safe_load_all(_stream(GREENLAND)) if doc],
            source="one.yaml",
        )

        assert "gl-00009" not in [p["key"] for p in plans[0].participants]

    def test_a_document_missing_community_id_names_which_document(self):
        """With several in a stream, "which one" is the whole question."""
        with pytest.raises(ValueError, match="document 2"):
            _load_communities(
                [
                    {"community": {"id": "greenland"}},
                    {"members": {}},
                ],
                source="two.yaml",
            )

    def test_one_community_declared_twice_is_refused(self):
        """The second pass's member list would be the one that stands.

        The registry cannot emit this — `key` is unique — so it means a
        hand-assembled file, and provisioning the same REC twice from two
        disagreeing member lists is worse than refusing.
        """
        with pytest.raises(ValueError, match="greenland"):
            _load_communities(
                [
                    {"community": {"id": "greenland"}},
                    {"community": {"id": "greenland"}},
                ],
                source="two.yaml",
            )
