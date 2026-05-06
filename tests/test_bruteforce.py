from app.log_analyser.log_reporter import LogReporter
from app.log_analyser.log_analyser import LogAnalyser

def test_brute_force_detected():
    analyser = LogAnalyser()
    analyser.analyse("log_files/brute_force.log")

    reporter = LogReporter(analyser)

    results = reporter.detect_bruteforce(5, 10)

    assert len(results) > 0

def test_no_brute_force_detected():
    analyser = LogAnalyser()
    analyser.analyse("log_files/empty.log")

    reporter = LogReporter(analyser)

    results = reporter.detect_bruteforce(5, 10)

    assert len(results) == 0