from datetime import datetime

from celine.policies.audit.logger import AuditLogger
from celine.policies.models import (
    Action,
    Decision,
    PolicyInput,
    Resource,
    ResourceType,
    Subject,
    SubjectType,
)


class FakeStructLogger:
    def __init__(self):
        self.calls = []

    def info(self, **kwargs):
        self.calls.append(("info", kwargs))

    def warning(self, **kwargs):
        self.calls.append(("warning", kwargs))

    def error(self, **kwargs):
        self.calls.append(("error", kwargs))


def _make_input(subject: Subject | None) -> PolicyInput:
    return PolicyInput(
        subject=subject,
        resource=Resource(type=ResourceType.DATASET, id="ds-1", attributes={"access_level": "open"}),
        action=Action(name="read", context={}),
        environment={"request_id": "req-1", "timestamp": 123},
    )


def test_audit_logger_logs_allowed_as_info():
    fake = FakeStructLogger()
    audit = AuditLogger(enabled=True, log_inputs=False, logger=fake)

    decision = Decision(allowed=True, reason="ok", policy="celine.dataset.access")
    policy_input = _make_input(Subject(id="u1", type=SubjectType.USER, groups=["g"], scopes=[], claims={}))

    record = audit.log_decision(
        request_id="req-1",
        decision=decision,
        policy_input=policy_input,
        latency_ms=1.234,
        cached=False,
        source_service="svc",
    )

    assert record.request_id == "req-1"
    assert isinstance(record.timestamp, datetime)

    assert len(fake.calls) == 1
    level, payload = fake.calls[0]
    assert level == "info"
    assert payload["event"] == "policy_decision"
    assert payload["allowed"] is True
    assert payload["policy"] == "celine.dataset.access"
    assert payload["subject_id"] == "u1"
    assert payload["subject_type"] == "user"
    assert payload["resource_type"] == "dataset"
    assert payload["resource_id"] == "ds-1"
    assert payload["action"] == "read"
    assert payload["source_service"] == "svc"
    assert "input" not in payload


def test_audit_logger_logs_denied_as_warning_and_can_log_inputs():
    fake = FakeStructLogger()
    audit = AuditLogger(enabled=True, log_inputs=True, logger=fake)

    decision = Decision(allowed=False, reason="nope", policy="celine.dataset.access")
    policy_input = _make_input(None)

    audit.log_decision(
        request_id="req-2",
        decision=decision,
        policy_input=policy_input,
        latency_ms=9.9,
        cached=True,
        source_service=None,
    )

    assert len(fake.calls) == 1
    level, payload = fake.calls[0]
    assert level == "warning"
    assert payload["allowed"] is False
    assert payload["cached"] is True
    assert "input" in payload
    assert payload["input"]["subject"] is None


def test_audit_logger_log_error():
    fake = FakeStructLogger()
    audit = AuditLogger(enabled=True, log_inputs=True, logger=fake)

    audit.log_error(request_id="req-3", error="boom", policy_input=None, source_service="svc")

    assert len(fake.calls) == 1
    level, payload = fake.calls[0]
    assert level == "error"
    assert payload["event"] == "policy_error"
    assert payload["request_id"] == "req-3"
    assert payload["error"] == "boom"
    assert payload["source_service"] == "svc"


def test_audit_logger_disabled_no_calls():
    fake = FakeStructLogger()
    audit = AuditLogger(enabled=False, log_inputs=True, logger=fake)

    decision = Decision(allowed=True, reason="ok", policy="celine.dataset.access")
    policy_input = _make_input(None)

    audit.log_decision(request_id="req-x", decision=decision, policy_input=policy_input, latency_ms=0.1)
    audit.log_error(request_id="req-y", error="err", policy_input=None)

    assert fake.calls == []
