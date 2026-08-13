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

from celine.policies.cli.keycloak.client import ROLE_HIERARCHY
from celine.policies.cli.keycloak.commands._utils import (
    derive_username,
    load_rec_community_info,
    load_rec_operators,
    load_rec_participants,
)

# The shape rec-registry emits: community metadata, members keyed by
# participant code, and DSO operators under community.operators.
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
        user_id: 11111111-1111-1111-1111-111111111111
      gl-00002:
        name: Anna Bianchi
        user_id: 22222222-2222-2222-2222-222222222222
"""


def _write(tmp_path: Path, body: str, name: str = "rec.yaml") -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


@pytest.fixture
def rec_yaml(tmp_path: Path) -> Path:
    return _write(tmp_path, REC_YAML)


# ---------------------------------------------------------------------------
# Participants
# ---------------------------------------------------------------------------


class TestLoadRecParticipants:
    def test_it_reads_every_member(self, rec_yaml: Path):
        participants = load_rec_participants(rec_yaml)

        assert [p["key"] for p in participants] == ["gl-00001", "gl-00002"]
        assert participants[0]["user_id"] == "11111111-1111-1111-1111-111111111111"
        assert participants[0]["name"] == "Mario Rossi"

    def test_the_legacy_participants_key_still_works(self, tmp_path: Path):
        """Older REC files say `participants:`; those RECs still need syncing."""
        path = _write(
            tmp_path,
            """
            community:
              id: greenland
            participants:
              gl-00001:
                name: Mario Rossi
                user_id: uid-1
            """,
        )
        assert [p["key"] for p in load_rec_participants(path)] == ["gl-00001"]

    def test_members_wins_when_both_keys_are_present(self, tmp_path: Path):
        """A file mid-migration must not provision the stale list."""
        path = _write(
            tmp_path,
            """
            members:
              new-1:
                user_id: uid-new
            participants:
              old-1:
                user_id: uid-old
            """,
        )
        assert [p["key"] for p in load_rec_participants(path)] == ["new-1"]

    def test_a_member_without_a_user_id_is_skipped(self, tmp_path: Path):
        """`user_id` is the join key to the registry; a user without one is unlinkable.

        Skipped rather than invented — a generated id would create a Keycloak
        account nothing in the platform can match back to a REC member.
        """
        path = _write(
            tmp_path,
            """
            members:
              gl-00001:
                name: Has One
                user_id: uid-1
              gl-00002:
                name: Missing One
            """,
        )
        participants = load_rec_participants(path)

        assert [p["key"] for p in participants] == ["gl-00001"]

    def test_an_empty_user_id_is_skipped_too(self, tmp_path: Path):
        path = _write(tmp_path, "members:\n  gl-1:\n    user_id: ''\n")
        assert load_rec_participants(path) == []

    def test_the_skip_is_logged_with_the_member_key(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ):
        """The key is the only way to find the row to fix in the source file."""
        path = _write(tmp_path, "members:\n  gl-00007:\n    name: No Id\n")
        with caplog.at_level("WARNING"):
            load_rec_participants(path)

        assert "gl-00007" in caplog.text

    def test_a_missing_name_falls_back_to_the_key(self, tmp_path: Path):
        """Only a display name — a nameless account is worse than a coded one."""
        path = _write(tmp_path, "members:\n  gl-00001:\n    user_id: uid-1\n")
        assert load_rec_participants(path)[0]["name"] == "gl-00001"

    def test_a_file_with_no_members_yields_nothing(self, tmp_path: Path):
        path = _write(tmp_path, "community:\n  id: greenland\n")
        assert load_rec_participants(path) == []


# ---------------------------------------------------------------------------
# Operators (DSOs)
# ---------------------------------------------------------------------------


class TestLoadRecOperators:
    def test_it_reads_operators_with_their_metadata(self, rec_yaml: Path):
        operators = load_rec_operators(rec_yaml)

        assert len(operators) == 1
        assert operators[0] == {
            "id": "set-distribuzione",
            "name": "SET Distribuzione S.p.A.",
            "country": "IT",
            "contact": "info@setdistribuzione.it",
        }

    def test_a_missing_name_falls_back_to_the_id(self, tmp_path: Path):
        path = _write(
            tmp_path,
            """
            community:
              id: greenland
              operators:
                set-distribuzione: {}
            """,
        )
        assert load_rec_operators(path)[0]["name"] == "set-distribuzione"

    def test_optional_fields_come_back_as_none(self, tmp_path: Path):
        """`ensure_organization` sends contact as the description; absent is fine."""
        path = _write(
            tmp_path,
            """
            community:
              operators:
                dso-1:
                  name: DSO One
            """,
        )
        operator = load_rec_operators(path)[0]
        assert operator["country"] is None
        assert operator["contact"] is None

    def test_a_community_without_operators_yields_nothing(self, tmp_path: Path):
        path = _write(tmp_path, "community:\n  id: greenland\n")
        assert load_rec_operators(path) == []

    def test_an_explicitly_empty_operators_block_yields_nothing(self, tmp_path: Path):
        """`operators:` with nothing under it parses as None, not as a dict."""
        path = _write(tmp_path, "community:\n  id: greenland\n  operators:\n")
        assert load_rec_operators(path) == []

    def test_a_file_without_a_community_block_yields_nothing(self, tmp_path: Path):
        path = _write(tmp_path, "members: {}\n")
        assert load_rec_operators(path) == []


# ---------------------------------------------------------------------------
# Community metadata
# ---------------------------------------------------------------------------


class TestLoadRecCommunityInfo:
    def test_it_reads_the_community_block(self, rec_yaml: Path):
        info = load_rec_community_info(rec_yaml)

        assert info == {
            "id": "greenland",
            "name": "Greenland Energy Community",
            "description": "A REC in Trentino",
            "type": "rec",
        }

    def test_a_missing_id_is_a_hard_error(self, tmp_path: Path):
        """It becomes the organization alias every member is attached to.

        Defaulting it would provision a whole REC under a placeholder alias —
        far more work to unpick than a failed run.
        """
        path = _write(tmp_path, "community:\n  name: Nameless\n")
        with pytest.raises(ValueError, match="community.id"):
            load_rec_community_info(path)

    def test_the_error_names_the_offending_file(self, tmp_path: Path):
        """Operators pass several REC files; "which one" is the whole question."""
        path = _write(tmp_path, "members: {}\n", name="broken.rec.yaml")
        with pytest.raises(ValueError, match="broken.rec.yaml"):
            load_rec_community_info(path)

    def test_the_name_falls_back_to_the_id(self, tmp_path: Path):
        path = _write(tmp_path, "community:\n  id: greenland\n")
        assert load_rec_community_info(path)["name"] == "greenland"

    def test_the_description_defaults_to_empty(self, tmp_path: Path):
        path = _write(tmp_path, "community:\n  id: greenland\n")
        assert load_rec_community_info(path)["description"] == ""

    def test_the_type_defaults_to_rec(self, tmp_path: Path):
        """It lands in the KC organization's `type` attribute, which policies read."""
        path = _write(tmp_path, "community:\n  id: greenland\n")
        assert load_rec_community_info(path)["type"] == "rec"

    def test_an_explicit_type_is_kept(self, tmp_path: Path):
        path = _write(tmp_path, "community:\n  id: greenland\n  type: cer\n")
        assert load_rec_community_info(path)["type"] == "cer"


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

    def test_it_carries_no_personal_data(self, rec_yaml: Path):
        for participant in load_rec_participants(rec_yaml):
            username = derive_username(participant["key"])
            assert participant["name"].lower() not in username


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
