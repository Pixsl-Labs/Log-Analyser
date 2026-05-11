from app.log_analyser.log_reporter import LogReporter
from app.log_analyser.log_analyser import LogAnalyser
from conftest import brute_force_reporter, empty_reporter

def test_get_failed_logins_by_user_returns_results(brute_force_reporter):
    username = brute_force_reporter.analyser.failed_logins[0].user

    results = brute_force_reporter.get_failed_logins_by_user(username)

    assert len(results) > 0
    assert all(entry.user == username for entry in results)

def test_failed_logins_by_user_case_insensitive(brute_force_reporter):   
    username = ["admin", "ADMIN", "AdMiN"]

    for user_ in username:
        results = brute_force_reporter.get_failed_logins_by_user(user_)

        assert len(results) > 0
        assert all(entry.user.lower() == user_.lower() for entry in results)

def test_get_failed_logins_by_user_no_results(empty_reporter):
    username = "admin"

    results = empty_reporter.get_failed_logins_by_user(username)

    assert not results