from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

DEFAULT_LOG_FILE = "logs/hsm-client.log"
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_LOG_BACKUP_COUNT = 5


def _parse_int(value: str, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got: {value}") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be >= 0, got: {value}")
    return parsed


def configure_logging(
    *,
    log_file: str | Path | None = None,
    level: str | int | None = None,
    max_bytes: int | None = None,
    backup_count: int | None = None,
) -> logging.Logger:
    """
    Configure rotating file logging for the hsm_client logger namespace.

    Environment variable overrides:
    - HSM_CLIENT_LOG_FILE
    - HSM_CLIENT_LOG_LEVEL
    - HSM_CLIENT_LOG_MAX_BYTES
    - HSM_CLIENT_LOG_BACKUP_COUNT
    """

    resolved_log_file = Path(
        str(log_file or os.environ.get("HSM_CLIENT_LOG_FILE", DEFAULT_LOG_FILE))
    )
    resolved_level = level or os.environ.get("HSM_CLIENT_LOG_LEVEL", DEFAULT_LOG_LEVEL)
    if isinstance(resolved_level, str):
        normalized_level = resolved_level.strip().upper()
        if normalized_level.isdigit():
            numeric_level = int(normalized_level)
        else:
            numeric_level = getattr(logging, normalized_level, None)
            if not isinstance(numeric_level, int):
                raise ValueError(f"Invalid log level: {resolved_level}")
    else:
        numeric_level = int(resolved_level)

    if max_bytes is None:
        max_bytes = _parse_int(
            os.environ.get("HSM_CLIENT_LOG_MAX_BYTES", str(DEFAULT_LOG_MAX_BYTES)),
            "HSM_CLIENT_LOG_MAX_BYTES",
        )
    if backup_count is None:
        backup_count = _parse_int(
            os.environ.get("HSM_CLIENT_LOG_BACKUP_COUNT", str(DEFAULT_LOG_BACKUP_COUNT)),
            "HSM_CLIENT_LOG_BACKUP_COUNT",
        )
    if max_bytes < 0:
        raise ValueError("max_bytes must be >= 0.")
    if backup_count < 0:
        raise ValueError("backup_count must be >= 0.")

    resolved_log_file.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("hsm_client")
    logger.setLevel(numeric_level)
    logger.propagate = False

    resolved_path = resolved_log_file.resolve()
    for existing in logger.handlers:
        if (
            isinstance(existing, RotatingFileHandler)
            and Path(existing.baseFilename).resolve() == resolved_path
        ):
            existing.setLevel(numeric_level)
            return logger

    handler = RotatingFileHandler(
        resolved_log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setLevel(numeric_level)
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )
    logger.addHandler(handler)

    logger.info(
        "Configured rotating file logging (path=%s, level=%s, max_bytes=%d, backup_count=%d)",
        resolved_log_file,
        logging.getLevelName(numeric_level),
        max_bytes,
        backup_count,
    )
    return logger
