from conftest import (
    brute_force_reporter,
    empty_reporter,
    distributed_reporter
)


def test_get_suspicious_ips_returns_results(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_suspicious_ips()

    assert len(results) > 0


def test_get_suspicious_ips_by_ip(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_suspicious_ips(
        ip="192.168.1.10"
    )

    assert len(results) > 0

    assert all(
        result[0] == "192.168.1.10"
        for result in results
    )


def test_get_suspicious_ips_by_severity(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_suspicious_ips(
        severity="LOW"
    )

    assert len(results) > 0

    assert all(
        result[2] == "LOW"
        for result in results
    )


def test_get_suspicious_ips_no_results(
        empty_reporter
    ):

    results = empty_reporter.get_suspicious_ips()

    assert results == []


def test_get_bruteforce_returns_results(
        brute_force_reporter
    ):

    results = brute_force_reporter.get_bruteforce(
        5,
        10
    )

    assert len(results) > 0


def test_get_bruteforce_no_results(
        empty_reporter
    ):

    results = empty_reporter.get_bruteforce(
        5,
        10
    )

    assert results == []


def test_get_user_targeting_returns_results(
        distributed_reporter
    ):

    results = distributed_reporter.get_user_targeting(
        5
    )

    assert len(results) > 0


def test_get_user_targeting_no_results(
        empty_reporter
    ):

    results = empty_reporter.get_user_targeting(
        5
    )

    assert results == []