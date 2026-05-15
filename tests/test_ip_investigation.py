from app.log_analyser.log_reporter import LogReporter
from app.log_analyser.log_analyser import LogAnalyser


def test_get_activity_by_ip_returns_results():
    analyser = LogAnalyser()
    analyser.analyse("log_files/brute_force.log")

    ip = analyser.failed_logins[0].ip

    reporter = LogReporter(analyser)

    results = reporter.get_activity_timeline(
        ip=ip
    )

    assert len(results) > 0
    assert all(entry.ip == ip for entry in results)


def test_get_activity_by_ip_includes_failed_logins():
    analyser = LogAnalyser()
    analyser.analyse("log_files/brute_force.log")

    ip = analyser.failed_logins[0].ip

    reporter = LogReporter(analyser)

    results = reporter.get_activity_timeline(
        ip=ip
    )

    assert any(entry.status == "FAILED" for entry in results)


def test_get_activity_by_ip_includes_successful_logins():
    analyser = LogAnalyser()
    analyser.analyse("log_files/combined_attack.log")

    ip = analyser.successful_logins[0].ip

    reporter = LogReporter(analyser)

    results = reporter.get_activity_timeline(
        ip=ip
    )

    assert any(entry.status == "SUCCESS" for entry in results)


def test_get_activity_by_ip_no_results():
    analyser = LogAnalyser()
    analyser.analyse("log_files/empty.log")

    ip = "192.168.1.10"

    reporter = LogReporter(analyser)

    results = reporter.get_activity_timeline(
        ip=ip
    )

    assert not results