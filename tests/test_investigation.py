from datetime import time

from conftest import (
    brute_force_reporter,
    empty_reporter
)


def test_get_activity_timeline_returns_results(
        brute_force_reporter
    ):

    results = (
        brute_force_reporter.get_activity_timeline()
    )

    assert len(results) > 0


def test_get_activity_timeline_by_ip(
        brute_force_reporter
    ):

    results = (
        brute_force_reporter.get_activity_timeline(
            ip="192.168.1.10"
        )
    )

    assert len(results) > 0

    assert all(
        entry.ip == "192.168.1.10"
        for entry in results
    )


def test_get_activity_timeline_by_username(
        brute_force_reporter
    ):

    results = (
        brute_force_reporter.get_activity_timeline(
            username="root"
        )
    )

    assert len(results) > 0

    assert all(
        entry.user.lower() == "root"
        for entry in results
    )


def test_get_activity_timeline_time_range(
        brute_force_reporter
    ):

    results = (
        brute_force_reporter.get_activity_timeline(
            start_time=time(12, 0, 0),
            end_time=time(12, 0, 5)
        )
    )

    assert len(results) > 0

    assert all(
        time(12, 0, 0)
        <= entry.timestamp.time()
        <= time(12, 0, 5)
        for entry in results
    )


def test_get_activity_timeline_no_results(
        empty_reporter
    ):

    results = (
        empty_reporter.get_activity_timeline()
    )

    assert results == []


def test_get_suspicious_activity_returns_results(
        brute_force_reporter
    ):

    results = (
        brute_force_reporter.get_suspicious_activity()
    )

    assert len(results) > 0


def test_get_suspicious_activity_by_ip(
        brute_force_reporter
    ):

    results = (
        brute_force_reporter.get_suspicious_activity(
            ip="192.168.1.10"
        )
    )

    assert len(results) > 0

    assert all(
        entry.ip == "192.168.1.10"
        for entry in results
    )


def test_get_suspicious_activity_by_username(
        brute_force_reporter
    ):

    results = (
        brute_force_reporter.get_suspicious_activity(
            username="root"
        )
    )

    assert len(results) > 0

    assert all(
        entry.user.lower() == "root"
        for entry in results
    )


def test_get_suspicious_activity_by_severity(
        brute_force_reporter
    ):

    results = (
        brute_force_reporter.get_suspicious_activity(
            severity="LOW"
        )
    )

    assert len(results) > 0

    assert all(
        entry.severity == "LOW"
        for entry in results
    )


def test_get_suspicious_activity_time_range(
        brute_force_reporter
    ):

    results = (
        brute_force_reporter.get_suspicious_activity(
            start_time=time(12, 0, 0),
            end_time=time(12, 0, 5)
        )
    )

    assert len(results) > 0

    assert all(
        time(12, 0, 0)
        <= entry.timestamp.time()
        <= time(12, 0, 5)
        for entry in results
    )


def test_get_suspicious_activity_no_results(
        empty_reporter
    ):

    results = (
        empty_reporter.get_suspicious_activity()
    )

    assert results == []