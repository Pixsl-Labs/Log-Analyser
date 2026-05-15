from app.log_analyser.log_reporter import LogReporter
from app.log_analyser.log_analyser import LogAnalyser
from conftest import brute_force_reporter, empty_reporter

def test_attack_statistics_returns_dictionary(brute_force_reporter):
    results = brute_force_reporter.get_attack_statistics()

    assert isinstance(results, dict)

def test_attack_statistics_contains_expected_keys(brute_force_reporter):
    results = brute_force_reporter.get_attack_statistics()

    expected_keys = {
            "failed_attempts",
            "successful_logins",
            "suspicious_ips",
            "brute_force_alerts",
            "targeted_users",
            "highest_severity",
            "top_attacker",
            "most_targeted_user"
        }

    assert all(key in results for key in expected_keys)

def test_attack_statistics_values_are_correct(brute_force_reporter):
    results = brute_force_reporter.get_attack_statistics()

    expected_results = {
            "failed_attempts": 5,
            "successful_logins": 1,
            "suspicious_ips": 1,
            "brute_force_alerts": 1,
            "targeted_users": 1,
            "highest_severity": "LOW",
            "top_attacker": "192.168.1.10 (5 attempts)",
            "most_targeted_user": "root (5 attempts)"
        }
    
    assert results == expected_results

def test_attack_statistics_empty_log(empty_reporter):
    results = empty_reporter.get_attack_statistics()

    expected_results = {
            "failed_attempts": 0,
            "successful_logins": 0,
            "suspicious_ips": 0,
            "brute_force_alerts": 0,
            "targeted_users": 0,
            "highest_severity": "NONE",
            "top_attacker": None,
            "most_targeted_user": None
        }
    
    assert results == expected_results