"""Structured audit logging for policy decisions."""

import sys
from datetime import datetime, timezone
from typing import Any

import logging
import structlog

from celine.policies.models import AuditRecord, Decision, PolicyInput


def configure_audit_logging(
    *,
    log_level: str | int,
    json_format: bool,
    service_name: str,
) -> None:
    # Resolve log level via stdlib logging (NOT structlog)
    if isinstance(log_level, str):
        level = getattr(logging, log_level.upper(), logging.INFO)
    else:
        level = int(log_level)

    logging.basicConfig(level=level)

    processors = [
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if json_format:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


class AuditLogger:
    """Audit logger for policy decisions."""

    def __init__(
        self,
        enabled: bool = True,
        log_inputs: bool = True,
        logger: Any = None,
    ):
        """Initialize audit logger.

        Args:
            enabled: Whether audit logging is enabled
            log_inputs: Whether to log full inputs (may be sensitive)
            logger: Optional custom logger
        """
        self._enabled = enabled
        self._log_inputs = log_inputs
        self._logger = logger or structlog.get_logger("audit")

    def log_decision(
        self,
        request_id: str,
        decision: Decision,
        policy_input: PolicyInput,
        latency_ms: float,
        cached: bool = False,
        source_service: str | None = None,
    ) -> AuditRecord:
        """Log a policy decision.

        Args:
            request_id: Unique request identifier
            decision: Policy decision
            policy_input: Policy input
            latency_ms: Evaluation latency
            cached: Whether result was from cache
            source_service: Calling service identifier

        Returns:
            AuditRecord for the logged decision
        """
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc),
            request_id=request_id,
            decision=decision,
            input=policy_input,
            latency_ms=latency_ms,
            cached=cached,
            source_service=source_service,
        )

        if self._enabled:
            log_data: dict[str, Any] = {
                "event": "policy_decision",
                "request_id": request_id,
                "allowed": decision.allowed,
                "policy": decision.policy,
                "reason": decision.reason,
                "latency_ms": round(latency_ms, 2),
                "cached": cached,
            }

            # Add subject info
            if policy_input.subject:
                log_data["subject_id"] = policy_input.subject.id
                log_data["subject_type"] = policy_input.subject.type.value

            # Add resource info
            log_data["resource_type"] = policy_input.resource.type.value
            log_data["resource_id"] = policy_input.resource.id
            log_data["action"] = policy_input.action.name

            # Add source service
            if source_service:
                log_data["source_service"] = source_service

            # Add full input if enabled
            if self._log_inputs:
                log_data["input"] = {
                    "subject": policy_input.subject.model_dump() if policy_input.subject else None,
                    "resource": policy_input.resource.model_dump(),
                    "action": policy_input.action.model_dump(),
                }

            # Log at appropriate level
            if decision.allowed:
                self._logger.info(**log_data)
            else:
                self._logger.warning(**log_data)

        return record

    def log_error(
        self,
        request_id: str,
        error: str,
        policy_input: PolicyInput | None = None,
        source_service: str | None = None,
    ) -> None:
        """Log a policy evaluation error.

        Args:
            request_id: Unique request identifier
            error: Error message
            policy_input: Policy input (if available)
            source_service: Calling service identifier
        """
        if not self._enabled:
            return

        log_data: dict[str, Any] = {
            "event": "policy_error",
            "request_id": request_id,
            "error": error,
        }

        if source_service:
            log_data["source_service"] = source_service

        if policy_input:
            log_data["resource_type"] = policy_input.resource.type.value
            log_data["resource_id"] = policy_input.resource.id
            log_data["action"] = policy_input.action.name

        self._logger.error(**log_data)
