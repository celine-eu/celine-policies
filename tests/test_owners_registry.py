"""`load_owners` — the registry that decides which Keycloak organizations exist.

``sync-orgs`` provisions real identities from these files, and the loader's
failure mode was quiet: an entry it could not identify was skipped with a log
line, so a mistyped key produced a run that reported success and simply created
one organization fewer. That surfaces later as an authorization failure with
nothing pointing back to the typo.

``owners.schema.json`` had described the format precisely all along —
``additionalProperties: false``, a ``type`` enum, required ``id``/``type``/``name``
— and nothing had ever executed it. It is executed here now, per file, before
the merge.

The unhappy paths below are the ones that used to be silent. Each asserts that
the file is *rejected*, not that it is repaired: guessing what a typo meant is
how one deployment's registry stops matching another's.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from celine.governance import GovernanceValidationError

from celine.policies.cli.keycloak.commands._utils import load_owners

BASE = textwrap.dedent(
    """
    owners:
      - id: greenland
        type: schema:NGO
        name: Greenland Soc. Coop.
        url: https://www.greenland.it
        organization:
          create: true
          role: rec
          attributes:
            country: IT
        aliases: [rec]

      - id: spxl
        type: schema:Corporation
        name: Spindox Labs srl
        url: https://spindoxlabs.com/en
    """
)

# A deployment overlay: replaces one entry, adds another, leaves the rest alone.
OVERLAY = textwrap.dedent(
    """
    owners:
      - id: greenland
        type: schema:NGO
        name: Greenland Soc. Coop. (staging)
        url: https://staging.greenland.it
        organization:
          create: false

      - id: set-distribuzione
        type: schema:Corporation
        name: SET Distribuzione S.p.A.
        url: https://www.setdistribuzione.it
        organization:
          create: true
          role: dso
    """
)


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# happy paths
# ---------------------------------------------------------------------------


def test_a_valid_registry_loads_with_its_keycloak_block(tmp_path: Path) -> None:
    owners = load_owners([_write(tmp_path, "owners.yaml", BASE)])
    assert [o["id"] for o in owners] == ["greenland", "spxl"]

    greenland = owners[0]["organization"]
    assert greenland["create"] is True
    assert greenland["role"] == "rec"
    # free-form attributes reach the KC org alongside the role
    assert greenland["attributes"] == {"country": "IT"}


def test_later_files_shadow_earlier_entries_by_id(tmp_path: Path) -> None:
    """The reason this keeps its own loader rather than the canonical one."""
    owners = load_owners(
        [
            _write(tmp_path, "owners.yaml", BASE),
            _write(tmp_path, "owners.local.yaml", OVERLAY),
        ]
    )
    by_id = {o["id"]: o for o in owners}

    assert set(by_id) == {"greenland", "spxl", "set-distribuzione"}
    # replaced wholesale, not merged field-wise
    assert by_id["greenland"]["name"] == "Greenland Soc. Coop. (staging)"
    assert by_id["greenland"]["url"] == "https://staging.greenland.it"
    # untouched by the overlay
    assert by_id["spxl"]["name"] == "Spindox Labs srl"


def test_an_overlay_can_withdraw_a_keycloak_organization(tmp_path: Path) -> None:
    """`create: false` must actually take effect — shadowing replaces the entry."""
    owners = load_owners(
        [
            _write(tmp_path, "owners.yaml", BASE),
            _write(tmp_path, "owners.local.yaml", OVERLAY),
        ]
    )
    provisioned = {
        o["id"] for o in owners if (o.get("organization") or {}).get("create")
    }
    assert provisioned == {"set-distribuzione"}


def test_owners_without_an_organization_block_are_not_provisioned(
    tmp_path: Path,
) -> None:
    owners = load_owners([_write(tmp_path, "owners.yaml", BASE)])
    assert "organization" not in owners[1]  # spxl is a publisher, not a KC org


def test_role_is_accepted_alongside_the_keycloak_role(tmp_path: Path) -> None:
    """Two fields named `role`; the schema must permit both without confusion."""
    body = textwrap.dedent(
        """
        owners:
          - id: greenland
            type: schema:NGO
            name: Greenland
            role: controller
            organization:
              create: true
              role: rec
        """
    )
    owner = load_owners([_write(tmp_path, "owners.yaml", body)])[0]
    assert owner["role"] == "controller"
    assert owner["organization"]["role"] == "rec"


# ---------------------------------------------------------------------------
# unhappy paths — each of these used to load "successfully"
# ---------------------------------------------------------------------------


def test_a_mistyped_organization_key_is_rejected(tmp_path: Path) -> None:
    """The exact silent failure: British spelling, zero organizations, exit 0."""
    body = BASE.replace("organization:", "organisation:")
    with pytest.raises(GovernanceValidationError) as exc:
        load_owners([_write(tmp_path, "owners.yaml", body)])
    assert "organisation" in str(exc.value)


def test_an_entry_without_an_id_is_rejected(tmp_path: Path) -> None:
    """It was skipped with a debug log — one fewer org, no error anywhere."""
    body = "owners:\n  - type: schema:NGO\n    name: No Identifier\n"
    with pytest.raises(GovernanceValidationError) as exc:
        load_owners([_write(tmp_path, "owners.yaml", body)])
    assert "id" in str(exc.value)


def test_an_unknown_schema_type_is_rejected(tmp_path: Path) -> None:
    """`type` drives the JSON-LD @type downstream; a typo must not reach it."""
    body = BASE.replace("type: schema:NGO", "type: schema:Charity")
    with pytest.raises(GovernanceValidationError) as exc:
        load_owners([_write(tmp_path, "owners.yaml", body)])
    assert "schema:Charity" in str(exc.value)


def test_a_malformed_overlay_fails_the_whole_load(tmp_path: Path) -> None:
    """Every file is checked, not just the first — an overlay provisions too."""
    with pytest.raises(GovernanceValidationError) as exc:
        load_owners(
            [
                _write(tmp_path, "owners.yaml", BASE),
                _write(tmp_path, "owners.local.yaml", OVERLAY.replace("url:", "urls:")),
            ]
        )
    assert "owners.local.yaml" in str(exc.value)


def test_the_error_names_the_file_that_failed(tmp_path: Path) -> None:
    """With several registries in play, "which one" is the whole question."""
    bad = _write(tmp_path, "owners.broken.yaml", "owners:\n  - name: nameless\n")
    with pytest.raises(GovernanceValidationError) as exc:
        load_owners([bad])
    assert str(bad) in str(exc.value)
