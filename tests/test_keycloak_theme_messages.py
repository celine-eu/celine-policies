"""The `rec` Keycloak theme: every message key a template uses exists in every language.

This is the one theme check that needs no Keycloak. A key missing from a bundle is
not an error in Keycloak — the page prints the key itself — which is exactly how
the page every invitation ends on came to show `accountUpdatedTitle` as its title
(measured, `a-participant-is-invited-and-sets-their-own-password` Phase 1).

What it cannot see: whether Keycloak accepts a template, how it renders, and the
keys resolved from the `base` theme. Those are named in `INHERITED` below, and were
checked against the 26.7.3 `keycloak-themes` jar when they were listed; a Keycloak
upgrade that drops one is not caught here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

THEME = Path(__file__).resolve().parents[1] / "keycloak" / "themes" / "rec"

#: Keys a template uses and deliberately leaves to Keycloak's `base` theme, per
#: theme type. Anything used and not listed here must be in every bundle.
INHERITED: dict[str, set[str]] = {
    "login": {
        "doTryAnotherWay",
        "emailInstruction",
        "emailInstructionUsername",
        "loginOtpOneTime",
        "restartLoginTooltip",
    },
    "email": set(),
}

#: The languages the platform speaks: the webapp's, and the `locale` enum the
#: provisioning service accepts.
PLATFORM_LOCALES = {"it", "en", "es"}

_MSG = re.compile(r'msg\(\s*"([^"]+)"')


def _theme_types() -> list[str]:
    return sorted(p.name for p in THEME.iterdir() if (p / "theme.properties").exists())


def _properties(path: Path) -> dict[str, str]:
    """A Java `.properties` file, as far as message bundles use it."""
    entries: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        key, _, value = line.partition("=")
        entries[key.strip()] = value.strip()
    return entries


def _declared_locales(theme_type: str) -> set[str]:
    props = _properties(THEME / theme_type / "theme.properties")
    return {loc.strip() for loc in props.get("locales", "").split(",") if loc.strip()}


def _bundles(theme_type: str) -> dict[str, dict[str, str]]:
    return {
        path.stem.removeprefix("messages_"): _properties(path)
        for path in sorted((THEME / theme_type / "messages").glob("messages_*.properties"))
    }


def _used_keys(theme_type: str) -> dict[str, set[str]]:
    """Static keys used by each template. `msg("requiredAction.${x}")` is dynamic
    and resolved from `base`, so it is skipped."""
    used: dict[str, set[str]] = {}
    for ftl in sorted((THEME / theme_type).rglob("*.ftl")):
        keys = {k for k in _MSG.findall(ftl.read_text(encoding="utf-8")) if "${" not in k}
        if keys:
            used[str(ftl.relative_to(THEME))] = keys
    return used


def test_the_theme_has_a_login_and_an_email_part():
    assert {"login", "email"} <= set(_theme_types())


@pytest.mark.parametrize("theme_type", _theme_types())
def test_every_declared_locale_is_a_platform_locale_with_a_bundle(theme_type):
    declared = _declared_locales(theme_type)

    assert declared == PLATFORM_LOCALES
    assert set(_bundles(theme_type)) == declared


@pytest.mark.parametrize("theme_type", _theme_types())
def test_every_key_a_template_uses_is_in_every_bundle(theme_type):
    bundles = _bundles(theme_type)
    inherited = INHERITED.get(theme_type, set())

    missing = sorted(
        f"{template}: {key} (messages_{locale})"
        for template, keys in _used_keys(theme_type).items()
        for key in keys - inherited
        for locale, entries in bundles.items()
        if key not in entries
    )

    assert missing == []


@pytest.mark.parametrize("theme_type", _theme_types())
def test_the_bundles_define_the_same_keys(theme_type):
    """A key translated in one language and not another falls back silently."""
    bundles = _bundles(theme_type)
    every = set().union(*(set(entries) for entries in bundles.values()))

    gaps = {locale: sorted(every - set(entries)) for locale, entries in bundles.items()}

    assert all(not keys for keys in gaps.values()), gaps


@pytest.mark.parametrize("theme_type", _theme_types())
def test_an_apostrophe_is_doubled_for_message_format(theme_type):
    """Keycloak formats every message through `MessageFormat`, where a lone `'`
    starts a quoted section and swallows the placeholder after it."""
    lone = re.compile(r"(?<!')'(?!')")

    offenders = sorted(
        f"messages_{locale}: {key}"
        for locale, entries in _bundles(theme_type).items()
        for key, value in entries.items()
        if lone.search(value)
    )

    assert offenders == []


def test_the_login_bundles_label_every_language_in_the_picker():
    """Without `locale_es`, the language picker showed Spanish as `es`."""
    for locale, entries in _bundles("login").items():
        for language in PLATFORM_LOCALES:
            assert f"locale_{language}" in entries, (locale, language)


def test_the_info_page_resolves_its_header_key():
    """`messageHeader` is a key. Printed raw it was the page's title."""
    info = (THEME / "login" / "info.ftl").read_text(encoding="utf-8")

    assert not re.search(r'(?<!")\$\{messageHeader\}', info)
    assert 'msg("${messageHeader}")' in info


@pytest.mark.parametrize(
    "template", ["executeActions.ftl", "password-reset.ftl", "email-verification.ftl"]
)
def test_each_email_has_an_html_and_a_text_part(template):
    assert (THEME / "email" / "html" / template).exists()
    assert (THEME / "email" / "text" / template).exists()


def test_email_expiry_goes_through_the_formatter():
    """`linkExpiration` is minutes, rendered `10,080` (measured)."""
    for ftl in (THEME / "email").rglob("*.ftl"):
        text = ftl.read_text(encoding="utf-8")
        assert "${linkExpiration}" not in text, ftl.name
        if "linkExpiration" in text:
            assert "linkExpirationFormatter(linkExpiration)" in text, ftl.name


def test_text_emails_are_plain_text_and_html_emails_never_unescape_the_model():
    """Auto-escaping applies to the text part unless it says it is plain text,
    which puts `&amp;` into a text email. In HTML, `?no_esc` on anything from
    the model would let a name be markup."""
    for ftl in (THEME / "email" / "text").glob("*.ftl"):
        text = ftl.read_text(encoding="utf-8")
        assert text.startswith('<#ftl output_format="plainText">'), ftl.name
    for ftl in (THEME / "email" / "html").glob("*.ftl"):
        assert "?no_esc" not in ftl.read_text(encoding="utf-8"), ftl.name


def test_the_invitation_copy_says_the_person_signs_in_afterwards():
    """Completing an invitation creates no session (measured, Phase 1): the next
    thing the person sees is the login form, and the email must not promise
    otherwise."""
    for locale, entries in _bundles("email").items():
        assert "recInvitationAfter" in entries, locale
    assert "sign in" in _bundles("email")["en"]["recInvitationAfter"]
