"""Structured logging with automatic redaction of anything that looks like
a secret (API keys, tokens, passwords) before it ever hits a log line."""
from __future__ import annotations

import logging
import re
import sys

_SECRET_PATTERNS = [
    re.compile(r"(api[_-]?key\s*=\s*)([^\s&]+)", re.IGNORECASE),
    re.compile(r"(token\s*=\s*)([^\s&]+)", re.IGNORECASE),
    re.compile(r"(password\s*=\s*)([^\s&]+)", re.IGNORECASE),
    re.compile(r"(Authorization:\s*Bearer\s+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(gh[pousr]_[A-Za-z0-9]{20,})"),  # GitHub token shapes
]


def redact(text: str) -> str:
    out = text
    for pat in _SECRET_PATTERNS:
        if pat.groups >= 2:
            out = pat.sub(lambda m: f"{m.group(1)}[REDACTED]", out)
        else:
            out = pat.sub("[REDACTED]", out)
    return out


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(str(record.msg))
        except Exception:
            pass
        return True


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
            )
        )
        handler.addFilter(RedactingFilter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
