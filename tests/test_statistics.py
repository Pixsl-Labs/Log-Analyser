from conftest import brute_force_reporter

from datetime import time


def test_get_failed_logins_returns_all(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_failed_logins()

    assert len(results) > 0

def test_get_failed_logins_by_ip(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_failed_logins(
        ip="192.168.1.10"
    )
    
    assert len(results) > 0

    assert all(
        entry.ip == "192.168.1.10"
        for entry in results
    )

def test_get_failed_logins_by_username(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_failed_logins(
        username="root"
    )
    

    assert len(results) > 0

    assert all(
        entry.user.lower() == "root"
        for entry in results
    )

def test_get_failed_logins_username_case_insensitive(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_failed_logins(
        username="ROOT"
    )

    assert len(results) > 0

    assert all(
        entry.user.lower() == "root"
        for entry in results
    )

def test_get_failed_logins_by_severity(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_failed_logins(
        severity="LOW"
    )

    assert len(results) > 0

    assert all(
        entry.severity == "LOW"
        for entry in results
    )

def test_get_failed_logins_by_status(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_failed_logins(
        status="FAILED"
    )

    assert len(results) > 0

    assert all(
        entry.status == "FAILED"
        for entry in results
    )

def test_get_failed_logins_no_results(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_failed_logins(
        ip="999.999.999.999"
    )

    assert results == []

def test_get_failed_logins_multiple_filters(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_failed_logins(
        ip="192.168.1.10",
        severity="LOW",
        status="FAILED"
    )

    assert len(results) > 0

    assert all(
        entry.ip == "192.168.1.10"
        and entry.severity == "LOW"
        and entry.status == "FAILED"
        for entry in results
    )

def test_get_failed_logins_time_range(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_failed_logins(
        start_time=time(12, 0, 0),
        end_time=time(12, 0, 5)
    )

    assert len(results) > 0

    assert all(
        time(12, 0, 0)
        <= entry.timestamp.time()
        <= time(12, 0, 5)
        for entry in results
    )

def test_get_failed_logins_time_range_no_results(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_failed_logins(
        start_time=time(23, 0, 0),
        end_time=time(23, 5, 0)
    )

    assert results == []

def test_get_successful_logins_returns_results(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_successful_logins()

    assert len(results) > 0

def test_get_successful_logins_by_ip(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_successful_logins(
        ip="192.168.1.10"
    )
    
    assert len(results) > 0

    assert all(
        entry.ip == "192.168.1.10"
        for entry in results
    )

def test_get_successful_logins_by_username(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_successful_logins(
        username="root"
    )
    

    assert len(results) > 0

    assert all(
        entry.user.lower() == "root"
        for entry in results
    )

def test_get_successful_logins_by_severity(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_successful_logins(
        status="SUCCESS"
    )

    assert len(results) > 0

    assert all(
        entry.status == "SUCCESS"
        for entry in results
    )

def test_get_successful_logins_no_results(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_successful_logins(
        ip="999.999.999.999"
    )

    assert results == []