import logging

from celine.policies.config import settings


def configure_logging() -> None:
    # Accept both standard level names (e.g. "INFO") and numeric values.
    raw = str(settings.log_level).upper()
    level = getattr(logging, raw, None)
    if not isinstance(level, int):
        try:
            level = int(settings.log_level)  # type: ignore[arg-type]
        except Exception:
            level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
