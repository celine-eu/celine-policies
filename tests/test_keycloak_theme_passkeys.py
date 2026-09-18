"""The `rec` login theme runs Keycloak's passkey pages, and they look like `rec`.

Measured on a throwaway 26.7.3 (plan participants-may-choose-a-passkey-or-a-one-time-code):

- `rec`'s `template.ftl` had no import map, so Keycloak's `webauthnRegister.js` and
  `webauthnAuthenticate.js` failed on `import ... from "rfc4648"`. "Register" did nothing
  and no passkey could be enrolled;
- `rec`'s `login.ftl` had no passkey button and no `username webauthn` autofill, so a
  passkey could not be used to sign in either;
- the pages `rec` inherits from `keycloak` (TOTP, recovery codes, passkey registration)
  showed PatternFly's blue primary buttons, a squeezed recovery-code warning, codes
  numbered twice, and a card taller than the screen overflowed above its top.

These are static checks on the files. What they cannot see is the rendering, which is
`tests/integration/test_imported_realm_login.py` and the plan's work directory.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LOGIN = REPO / "keycloak" / "themes" / "rec" / "login"
CSS = re.sub(r"/\*.*?\*/", "", (LOGIN / "resources" / "css" / "login.css").read_text(encoding="utf-8"), flags=re.S)
REALM_IMPORT = REPO / "config" / "keycloak" / "import" / "realm-celine.json"

#: Theme names Keycloak 26.7.3 lists (`GET /admin/serverinfo`, `themes`), without `rec`.
#: `keycloak.v2` is gone from the account themes.
KEYCLOAK_26_7_3_THEMES = {
    "account": {"keycloak.v3"},
    "admin": {"keycloak.v2"},
    "login": {"keycloak", "keycloak.v2"},
    "email": {"keycloak"},
}


def _rule(selector: str) -> str:
    """The declarations of the first rule whose selector list contains `selector`."""
    for match in re.finditer(r"([^{}]+)\{([^{}]*)\}", CSS):
        selectors = {s.strip() for s in match.group(1).split(",")}
        if selector in selectors:
            return match.group(2)
    raise AssertionError(f"no rule for {selector!r} in login.css")


def test_the_template_maps_rfc4648_for_keycloaks_webauthn_scripts():
    template = (LOGIN / "template.ftl").read_text(encoding="utf-8")
    block = re.search(r'<script type="importmap">(.*?)</script>', template, re.S)

    assert block, "template.ftl has no import map"
    imports = json.loads(block.group(1).replace("${url.resourcesCommonPath}", "COMMON"))["imports"]
    assert imports == {"rfc4648": "COMMON/vendor/rfc4648/rfc4648.js"}
    # it must precede any module script that imports it
    assert template.index('type="importmap"') < template.find("</head>")


def test_the_login_page_offers_a_passkey():
    login = (LOGIN / "login.ftl").read_text(encoding="utf-8")

    assert '<#import "passkeys.ftl" as passkeys>' in login
    assert "<@passkeys.conditionalUIData />" in login
    # the browser offers the passkey from the username field only with this token
    assert "then('username webauthn', 'username')" in login
    assert 'autocomplete="username"' not in login


@pytest.mark.parametrize("selector", [".pf-c-button.pf-m-primary", 'input[type="submit"].pf-c-button.pf-m-primary'])
def test_patternfly_primary_buttons_take_the_brand_colour(selector):
    assert "background: var(--color-primary)" in _rule(selector)


def test_secondary_buttons_are_not_filled():
    assert "background: transparent" in _rule('button[type="submit"].btn-default')


def test_the_passkey_button_is_a_full_width_button():
    rule = _rule("#authenticateWebAuthnButton")
    assert "width: 100%" in rule
    assert "border: 1px solid var(--color-primary)" in rule


def test_recovery_codes_are_numbered_once_and_the_warning_is_one_column():
    assert "list-style: none" in _rule("#kc-recovery-codes-list")
    assert "display: block" in _rule(".kc-recovery-codes-warning.pf-c-alert")


def test_a_tall_card_is_not_pushed_above_the_top_of_the_page():
    page = _rule(".login-pf-page")
    assert "justify-content: center" not in page
    content = _rule("#kc-content")
    assert "margin-top: auto" in content and "margin-bottom: auto" in content


def test_the_language_picker_has_its_own_row_on_a_phone():
    phone = re.search(r"@media \(max-width: 767px\) \{(.*?)\n\}", CSS, re.S)
    assert phone
    assert re.search(r"#kc-locale \{[^}]*position: static", phone.group(1))
    assert re.search(r"#kc-locale-dropdown \{[^}]*position: relative", phone.group(1))


@pytest.mark.parametrize("kind", ["account", "admin"])
def test_the_realm_import_names_themes_keycloak_ships(kind):
    """Keycloak accepts an unknown theme name and logs `Failed to find ACCOUNT theme` on
    every request (measured with `keycloak.v2`, which 26.7.3 no longer has)."""
    realm = json.loads(REALM_IMPORT.read_text(encoding="utf-8"))

    assert realm[f"{kind}Theme"] in KEYCLOAK_26_7_3_THEMES[kind]
