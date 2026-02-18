from __future__ import annotations

from pathlib import Path

from hsm_client import configure_logging


def test_configure_logging_creates_rotating_log_file(tmp_path: Path) -> None:
    log_file = tmp_path / "hsm-client.log"
    logger = configure_logging(
        log_file=log_file,
        level="INFO",
        max_bytes=1024,
        backup_count=2,
    )
    logger.info("logging test message")

    for handler in logger.handlers:
        handler.flush()

    assert log_file.exists()
    contents = log_file.read_text(encoding="utf-8")
    assert "logging test message" in contents
