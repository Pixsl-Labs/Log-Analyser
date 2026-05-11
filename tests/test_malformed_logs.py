from app.log_analyser.log_reporter import LogReporter
from app.log_analyser.log_analyser import LogAnalyser
from conftest import malformed_reporter

def test_malformed_log_does_not_crash(malformed_reporter):
    assert malformed_reporter is not None


def test_valid_entries_still_processed_from_malformed_log(malformed_reporter):
    analyser = malformed_reporter.analyser

    assert len(analyser.failed_logins) == 1
    assert len(analyser.successful_logins) == 1


def test_invalid_entries_are_skipped(malformed_reporter):
    analyser = malformed_reporter.analyser

    total_entries = (
        len(analyser.failed_logins)
        + len(analyser.successful_logins)
    )

    stats = malformed_reporter.get_attack_statistics()

    expected_valid_entries = (
        stats["failed_attempts"]
        + stats["successful_logins"]
    )

    assert total_entries == expected_valid_entries


def test_missing_ip_not_processed(malformed_reporter):
    analyser = malformed_reporter.analyser

    users = [entry.user for entry in analyser.failed_logins]

    assert "admin" not in users


def test_invalid_timestamp_not_processed(malformed_reporter):
    analyser = malformed_reporter.analyser

    users = [entry.user for entry in analyser.failed_logins]

    assert "test" not in users