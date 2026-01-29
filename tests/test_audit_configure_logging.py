import logging

import pytest

from celine.policies.audit.logger import configure_audit_logging


def test_configure_audit_logging_uses_stdlib_levels(monkeypatch):
    captured = {}

    def fake_basicConfig(*, level=None, **kwargs):
        captured["level"] = level

    import structlog
    orig_make = structlog.make_filtering_bound_logger

    def fake_make_filtering_bound_logger(level):
        captured["structlog_level"] = level
        return orig_make(level)

    monkeypatch.setattr(logging, "basicConfig", fake_basicConfig)
    monkeypatch.setattr(structlog, "make_filtering_bound_logger", fake_make_filtering_bound_logger)

    configure_audit_logging(log_level="INFO", json_format=True, service_name="test")

    assert captured["level"] == logging.INFO
    assert captured["structlog_level"] == logging.INFO


@pytest.mark.parametrize(
    "log_level, expected",
    [("debug", logging.DEBUG), ("WARNING", logging.WARNING), ("ERROR", logging.ERROR)],
)
def test_configure_audit_logging_level_names(monkeypatch, log_level, expected):
    captured = {}

    def fake_basicConfig(*, level=None, **kwargs):
        captured["level"] = level

    import structlog
    orig_make = structlog.make_filtering_bound_logger

    def fake_make_filtering_bound_logger(level):
        captured["structlog_level"] = level
        return orig_make(level)

    monkeypatch.setattr(logging, "basicConfig", fake_basicConfig)
    monkeypatch.setattr(structlog, "make_filtering_bound_logger", fake_make_filtering_bound_logger)

    configure_audit_logging(log_level=log_level, json_format=False, service_name="test")

    assert captured["level"] == expected
    assert captured["structlog_level"] == expected


def test_configure_audit_logging_numeric_level(monkeypatch):
    captured = {}

    def fake_basicConfig(*, level=None, **kwargs):
        captured["level"] = level

    import structlog
    orig_make = structlog.make_filtering_bound_logger

    def fake_make_filtering_bound_logger(level):
        captured["structlog_level"] = level
        return orig_make(level)

    monkeypatch.setattr(logging, "basicConfig", fake_basicConfig)
    monkeypatch.setattr(structlog, "make_filtering_bound_logger", fake_make_filtering_bound_logger)

    configure_audit_logging(log_level=20, json_format=True, service_name="test")

    assert captured["level"] == 20
    assert captured["structlog_level"] == 20
