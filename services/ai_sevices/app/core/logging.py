import logging
import sys

import structlog

from app.config import get_settings


def configure_logging() -> None:
    get_settings()  # warm the lru_cache / fail fast on bad env, not otherwise used here
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(),
    )


def get_logger():
    settings = get_settings()
    return structlog.get_logger(service=settings.service_name)
