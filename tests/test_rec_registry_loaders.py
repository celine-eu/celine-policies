"""Reading a `rec-registry` REC definition, ahead of provisioning users from it.

`sync-users` turns these dicts into real Keycloak users, organizations and group
memberships. The loaders are lenient by design — a REC file is authored by hand
and half-filled entries are normal — but leniency is exactly what needs pinning:
each `.get(...)` fallback below is a decision about what happens to a
participant whose record is incomplete, and the two failure modes are opposite.
Skipping too eagerly leaves a member unable to log in; skipping too little
creates a user with no stable identity.

The one place that must *not* be lenient is `community.id`: it becomes the
Keycloak organization alias every member is attached to.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

import yaml

from celine.policies.cli.keycloak.client import ROLE_HIERARCHY
from celine.policies.cli.keycloak.commands._utils import (
    derive_username,
    load_rec_community_info,
    load_rec_operators,
    load_rec_participants,
    participant_username,
    read_rec_documents,
)

# The shape rec-registry emits: community metadata, members keyed by
# participant code, and DSO operators under community.operators.
#
# `user_id` holds a **username**, which is what the registry matches against a
# token's `preferred_username`. This fixture used to put a UUID there — the one
# value that cannot work, and the mistake the field's name invites — which was
# harmless while the loader read the column only to check it was non-empty and
# is not harmless now that it names the account.
REC_YAML = """
    community:
      id: greenland
      name: Greenland Energy Community
      description: A REC in Trentino
      type: rec
      operators:
        set-distribuzione:
          name: SET Distribuzione S.p.A.
          country: IT
          contact: info@setdistribuzione.it
    members:
      gl-00001:
        name: Mario Rossi
        user_id: gl-00001
        status: active
      gl-00002:
        name: Anna Bianchi
        user_id: anna.bianchi@example.com
        status: active
"""


def _write(tmp_path: Path, body: str, name: str = "rec.yaml") -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def _doc(body: str) -> dict:
    """The loaders take a parsed bundle, so the fixtures hand them one.

    The same document reaches them from a file and from `GET /admin/export`;
    parsing here rather than in each loader is what keeps the two sources
    indistinguishable.
    """
    return yaml.safe_load(textwrap.dedent(body)) or {}


@pytest.fixture
def rec_doc() -> dict:
    return _doc(REC_YAML)


# ---------------------------------------------------------------------------
# Participants
# ---------------------------------------------------------------------------


class TestLoadRecParticipants:
    def test_it_reads_every_member(self, rec_doc: dict):
        participants = load_rec_participants(rec_doc)

        assert [p["key"] for p in participants] == ["gl-00001", "gl-00002"]
        assert participants[0]["user_id"] == "gl-00001"
        assert participants[0]["name"] == "Mario Rossi"

    def test_the_legacy_participants_key_still_works(self):
        """Older REC files say `participants:`; those RECs still need syncing."""
        doc = _doc(
            """
            community:
              id: greenland
            participants:
              gl-00001:
                name: Mario Rossi
                user_id: uid-1
            """
        )
        assert [p["key"] for p in load_rec_participants(doc)] == ["gl-00001"]

    def test_members_wins_when_both_keys_are_present(self):
        """A file mid-migration must not provision the stale list."""
        doc = _doc(
            """
            members:
              new-1:
                user_id: uid-new
            participants:
              old-1:
                user_id: uid-old
            """
        )
        assert [p["key"] for p in load_rec_participants(doc)] == ["new-1"]

    def test_a_member_without_a_user_id_is_kept(self):
        """It used to be dropped, and dropping it excluded the seed case.

        A hand-authored REC file is exactly where a row with no `user_id`
        appears, and that file is what this path exists to provision. The
        registry path cannot produce one — the column is non-nullable — so
        skipping bought nothing and cost the seed members their accounts.
        `participant_username` decides what such a row is called.
        """
        doc = _doc(
            """
            members:
              gl-00001:
                name: Has One
                user_id: uid-1
              gl-00002:
                name: Missing One
            """
        )
        participants = load_rec_participants(doc)

        assert [p["key"] for p in participants] == ["gl-00001", "gl-00002"]
        assert participants[1]["user_id"] is None

    def test_an_empty_user_id_is_kept_too(self):
        assert len(load_rec_participants(_doc("members:\n  gl-1:\n    user_id: ''\n"))) == 1

    def test_a_missing_user_id_is_logged_with_the_member_key(
        self, caplog: pytest.LogCaptureFixture
    ):
        """The key is the only way to find the row to fix in the source file."""
        with caplog.at_level("WARNING"):
            load_rec_participants(_doc("members:\n  gl-00007:\n    name: No Id\n"))

        assert "gl-00007" in caplog.text

    def test_a_missing_name_falls_back_to_the_key(self):
        """Only a display name — a nameless account is worse than a coded one."""
        doc = _doc("members:\n  gl-00001:\n    user_id: uid-1\n")
        assert load_rec_participants(doc)[0]["name"] == "gl-00001"

    def test_a_file_with_no_members_yields_nothing(self):
        assert load_rec_participants(_doc("community:\n  id: greenland\n")) == []

    def test_a_member_with_no_body_at_all_does_not_crash(self):
        """`gl-1:` with nothing under it parses as None, not as a dict."""
        participants = load_rec_participants(_doc("members:\n  gl-1:\n"))
        assert [p["key"] for p in participants] == ["gl-1"]


class TestOnlyActiveMembersAreProvisioned:
    """The registry keys a member `pending` before approval and `suspended` after
    withdrawal, and neither is somebody who should be handed a login.

    `status` is mandatory in the registry's bundle schema, so every real export
    carries it. A row with none was authored by hand, and those files predate the
    field — so absent is read as active rather than as pending, which would stop
    provisioning every seed REC on the day this landed.
    """

    @pytest.mark.parametrize("status", ["pending", "suspended", "inactive"])
    def test_a_non_active_member_is_skipped(self, status: str):
        doc = _doc(f"members:\n  gl-1:\n    user_id: uid-1\n    status: {status}\n")
        assert load_rec_participants(doc) == []

    def test_an_active_member_is_provisioned(self):
        doc = _doc("members:\n  gl-1:\n    user_id: uid-1\n    status: active\n")
        assert [p["key"] for p in load_rec_participants(doc)] == ["gl-1"]

    def test_a_member_with_no_status_is_treated_as_active(self):
        doc = _doc("members:\n  gl-1:\n    user_id: uid-1\n")
        participants = load_rec_participants(doc)
        assert [p["key"] for p in participants] == ["gl-1"]
        assert participants[0]["status"] == "active"

    def test_the_skip_is_logged_with_the_key_and_the_status(
        self, caplog: pytest.LogCaptureFixture
    ):
        with caplog.at_level("INFO"):
            load_rec_participants(
                _doc("members:\n  gl-00007:\n    user_id: uid-7\n    status: pending\n")
            )

        assert "gl-00007" in caplog.text
        assert "pending" in caplog.text

    def test_skipping_provisioning_is_not_disabling(self):
        """Nothing here revokes an account a suspended member already has.

        The loader's only power is to withhold a row from the provisioning
        loop. Disabling somebody is a different act, and `sync-users` never
        writes `enabled: false` — so a member suspended in the registry keeps
        whatever Keycloak account they have until something whose job that is
        takes it away.
        """
        doc = _doc("members:\n  gl-1:\n    user_id: uid-1\n    status: suspended\n")
        assert load_rec_participants(doc) == []


# ---------------------------------------------------------------------------
# Operators (DSOs)
# ---------------------------------------------------------------------------


class TestLoadRecOperators:
    def test_it_reads_operators_with_their_metadata(self, rec_doc: dict):
        operators = load_rec_operators(rec_doc)

        assert len(operators) == 1
        assert operators[0] == {
            "id": "set-distribuzione",
            "name": "SET Distribuzione S.p.A.",
            "country": "IT",
            "contact": "info@setdistribuzione.it",
        }

    def test_a_missing_name_falls_back_to_the_id(self):
        doc = _doc(
            """
            community:
              id: greenland
              operators:
                set-distribuzione: {}
            """
        )
        assert load_rec_operators(doc)[0]["name"] == "set-distribuzione"

    def test_optional_fields_come_back_as_none(self):
        """`ensure_organization` sends contact as the description; absent is fine."""
        doc = _doc(
            """
            community:
              operators:
                dso-1:
                  name: DSO One
            """
        )
        operator = load_rec_operators(doc)[0]
        assert operator["country"] is None
        assert operator["contact"] is None

    def test_a_community_without_operators_yields_nothing(self):
        assert load_rec_operators(_doc("community:\n  id: greenland\n")) == []

    def test_an_explicitly_empty_operators_block_yields_nothing(self):
        """`operators:` with nothing under it parses as None, not as a dict."""
        assert load_rec_operators(_doc("community:\n  id: greenland\n  operators:\n")) == []

    def test_a_file_without_a_community_block_yields_nothing(self):
        assert load_rec_operators(_doc("members: {}\n")) == []


# ---------------------------------------------------------------------------
# Community metadata
# ---------------------------------------------------------------------------


class TestLoadRecCommunityInfo:
    def test_it_reads_the_community_block(self, rec_doc: dict):
        info = load_rec_community_info(rec_doc)

        assert info == {
            "id": "greenland",
            "name": "Greenland Energy Community",
            "description": "A REC in Trentino",
            "type": "rec",
        }

    def test_a_missing_id_is_a_hard_error(self):
        """It becomes the organization alias every member is attached to.

        Defaulting it would provision a whole REC under a placeholder alias —
        far more work to unpick than a failed run.
        """
        with pytest.raises(ValueError, match="community.id"):
            load_rec_community_info(_doc("community:\n  name: Nameless\n"))

    def test_the_error_names_the_source(self):
        """Operators pass several REC files; "which one" is the whole question.

        The loader no longer sees a path, so the caller passes the name it used —
        which is also how a registry URL gets into the message.
        """
        with pytest.raises(ValueError, match="broken.rec.yaml"):
            load_rec_community_info(_doc("members: {}\n"), source="broken.rec.yaml")

    def test_the_name_falls_back_to_the_id(self):
        assert load_rec_community_info(_doc("community:\n  id: greenland\n"))["name"] == "greenland"

    def test_the_description_defaults_to_empty(self):
        assert load_rec_community_info(_doc("community:\n  id: greenland\n"))["description"] == ""

    def test_the_type_defaults_to_rec(self):
        """It lands in the KC organization's `type` attribute, which policies read."""
        assert load_rec_community_info(_doc("community:\n  id: greenland\n"))["type"] == "rec"

    def test_an_explicit_type_is_kept(self):
        doc = _doc("community:\n  id: greenland\n  type: cer\n")
        assert load_rec_community_info(doc)["type"] == "cer"


# ---------------------------------------------------------------------------
# Usernames
# ---------------------------------------------------------------------------


class TestDeriveUsername:
    """Derived from the participant code, never from a name or an email.

    Keycloak usernames are effectively permanent, and the code is both stable
    and free of personal data — which is what makes it safe to read out during a
    demo.
    """

    def test_it_lowercases_the_participant_key(self):
        assert derive_username("GL-00001") == "gl-00001"

    def test_an_already_lowercase_key_is_unchanged(self):
        assert derive_username("gl-00001") == "gl-00001"

    def test_it_is_deterministic(self):
        """Re-running `sync-users` has to find the same user, not create a second."""
        assert derive_username("gl-00001") == derive_username("gl-00001")

    def test_keys_differing_only_in_case_collide(self):
        """Two such keys in one REC file are the same account — worth knowing.

        Keycloak usernames are case-insensitive anyway, so this matches it
        rather than producing two records for one member.
        """
        assert derive_username("GL-1") == derive_username("gl-1")

    def test_it_carries_no_personal_data(self, rec_doc: dict):
        for participant in load_rec_participants(rec_doc):
            username = derive_username(participant["key"])
            assert participant["name"].lower() not in username


class TestParticipantUsername:
    """What an account is named is read from the row, not computed from the key.

    `Member.user_id` is a Keycloak username — the registry resolves every
    self-service call by matching it against `preferred_username` — so the row
    that owns the value is what names the account.

    This is the defect that had to be repaired before the source could be
    switched. Deriving from the key was invisible against a hand-maintained
    file, because the same hand wrote both columns. Against the live registry it
    creates a second account for every onboarded participant.
    """

    def test_it_prefers_the_user_id_the_row_holds(self):
        assert participant_username({"key": "gl-00001", "user_id": "mrossi"}) == "mrossi"

    def test_the_onboarding_shape_is_named_after_the_user_id(self):
        """`../onboarding` writes `key = submission.ref` and `user_id` = the
        username Keycloak returned, so these two columns genuinely disagree.

        Deriving here would create `20260912-a3f9c2` beside the account the
        participant already signs in with — once per onboarded member, on the
        first registry-backed run.
        """
        participant = {"key": "20260912-a3f9c2", "user_id": "alice@example.com"}
        assert participant_username(participant) == "alice@example.com"

    def test_a_row_with_no_user_id_falls_back_to_the_key(self):
        """The seed case, and the only one the fallback is for."""
        assert participant_username({"key": "GL-00001", "user_id": None}) == "gl-00001"

    def test_an_empty_user_id_falls_back_too(self):
        assert participant_username({"key": "gl-1", "user_id": ""}) == "gl-1"

    def test_whitespace_is_not_a_user_id(self):
        assert participant_username({"key": "gl-1", "user_id": "   "}) == "gl-1"

    def test_a_user_id_is_used_verbatim(self):
        """Not lowercased, not normalised, not validated.

        Keycloak holds the username; guessing at its shape is how the two
        writers came apart in the first place. A UUID in this column is a
        registry-side defect — the field's name invites it and nothing
        validates it — and it is not this loader's to silently repair: an
        account named after a UUID is visible, while a row quietly rewritten is
        not.
        """
        uuid = "11111111-1111-1111-1111-111111111111"
        assert participant_username({"key": "gl-1", "user_id": uuid}) == uuid
        assert participant_username({"key": "gl-1", "user_id": "MRossi"}) == "MRossi"

    def test_it_is_deterministic(self):
        """A re-run has to find the same account, not create a second."""
        participant = {"key": "gl-1", "user_id": "mrossi"}
        assert participant_username(participant) == participant_username(participant)

    def test_the_loaded_rows_carry_what_it_needs(self, rec_doc: dict):
        """The loader and the namer are used together; this pins the seam."""
        names = [participant_username(p) for p in load_rec_participants(rec_doc)]
        assert names == ["gl-00001", "anna.bianchi@example.com"]


# ---------------------------------------------------------------------------
# Reading the bundle off disk
# ---------------------------------------------------------------------------


class TestReadRecDocuments:
    """One community or many, a file and the export are the same bytes.

    `GET /admin/export` returns a multidocument stream whenever it covers more
    than one community, and a file somebody saved from it is that stream. So the
    reader splits documents rather than assuming one.
    """

    def test_a_single_community_file_yields_one_document(self, tmp_path: Path):
        path = _write(tmp_path, REC_YAML)
        docs = read_rec_documents(path)

        assert len(docs) == 1
        assert docs[0]["community"]["id"] == "greenland"

    def test_a_multidocument_stream_yields_one_per_community(self, tmp_path: Path):
        path = _write(
            tmp_path,
            """
            community:
              id: greenland
            members:
              gl-1:
                user_id: uid-1
            ---
            community:
              id: blueland
            members:
              bl-1:
                user_id: uid-2
            """,
        )
        docs = read_rec_documents(path)

        assert [d["community"]["id"] for d in docs] == ["greenland", "blueland"]

    def test_empty_documents_are_dropped(self, tmp_path: Path):
        """A trailing `---` is normal in a stream and is not a community."""
        path = _write(tmp_path, "community:\n  id: greenland\n---\n")
        assert len(read_rec_documents(path)) == 1

    def test_a_file_with_no_document_at_all_is_refused(self, tmp_path: Path):
        """Better a refusal naming the file than a run that provisions nobody."""
        path = _write(tmp_path, "\n# nothing here\n")
        with pytest.raises(ValueError, match="no YAML document"):
            read_rec_documents(path)


# ---------------------------------------------------------------------------
# The group hierarchy users are provisioned into
# ---------------------------------------------------------------------------


class TestRoleHierarchy:
    """The same four groups are created per organization and at realm level.

    Policies and the onboarding console match on these names, so a rename here
    silently drops authority for everyone already provisioned.
    """

    def test_the_hierarchy_is_the_expected_four(self):
        assert ROLE_HIERARCHY == ["admins", "managers", "editors", "viewers"]

    def test_it_runs_from_most_to_least_privileged(self):
        """`sync-users` puts new members in the last one; order is meaningful."""
        assert ROLE_HIERARCHY[0] == "admins"
        assert ROLE_HIERARCHY[-1] == "viewers"
