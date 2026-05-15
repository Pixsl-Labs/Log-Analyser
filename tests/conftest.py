import pytest

from app.log_analyser.log_analyser import LogAnalyser
from app.log_analyser.log_reporter import LogReporter


@pytest.fixture
def brute_force_reporter():
    analyser = LogAnalyser()
    analyser.analyse("tests/test_logs/brute_force.log")
    return LogReporter(analyser)


@pytest.fixture
def clean_reporter():
    analyser = LogAnalyser()
    analyser.analyse("tests/test_logs/clean.log")
    return LogReporter(analyser)


@pytest.fixture
def distributed_reporter():
    analyser = LogAnalyser()
    analyser.analyse("tests/test_logs/distributed_attack.log")
    return LogReporter(analyser)


@pytest.fixture
def malformed_reporter():
    analyser = LogAnalyser()
    analyser.analyse("tests/test_logs/malformed.log")
    return LogReporter(analyser)

@pytest.fixture
def empty_reporter():
    analyser = LogAnalyser()
    analyser.analyse("tests/test_logs/empty.log")
    return LogReporter(analyser)