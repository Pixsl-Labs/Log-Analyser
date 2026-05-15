from datetime import time

from app.log_analyser.log_entry import LogEntry


def filter_log_entries(
    entries: list[LogEntry],
    ip: str | None=None,
    username: str | None=None,
    severity: str | None=None,
    status: str | None=None,
    start_time: time | None=None,
    end_time: time | None=None
) -> list[LogEntry]:
    """
    Filters log entries using optional filters.
    """

    results = entries

    if ip:
        results = [
            entry for entry in results
            if entry.ip == ip
        ]

    if username:
        results = [
            entry for entry in results
            if entry.user.lower() == username.lower()
        ]

    if severity:
        results = [
            entry for entry in results
            if entry.severity == severity
        ]

    if status:
        results = [
            entry for entry in results
            if entry.status == status
        ]

    if start_time:
        results = [
            entry for entry in results
            if entry.timestamp
            and entry.timestamp.time() >= start_time
        ]

    if end_time:
        results = [
            entry for entry in results
            if entry.timestamp
            and entry.timestamp.time() <= end_time
        ]

    return results