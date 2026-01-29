import logging

from celine.policies import config as config_module
from celine.policies.logs import configure_logging


def test_settings_singleton_exists_and_matches_get_settings():
    assert hasattr(config_module, "settings")
    assert config_module.get_settings() is config_module.settings


def test_configure_logging_uses_settings_level(monkeypatch):
    # Default settings.log_level is INFO in config.py
    called = {}

    def fake_basicConfig(*, level=None, **kwargs):
        called["level"] = level

    monkeypatch.setattr(logging, "basicConfig", fake_basicConfig)
    configure_logging()
    assert called["level"] == logging.INFO
