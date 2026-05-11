import pytest

from app.log_analyser.log_analyser import LogAnalyser
from app.log_analyser.log_reporter import LogReporter


@pytest.fixture
def brute_force_reporter():
    analyser = LogAnalyser()

    analyser.analyse("log_files/brute_force.log")

    return LogReporter(analyser)


@pytest.fixture
def empty_reporter():
    analyser = LogAnalyser()

    analyser.analyse("log_files/empty.log")

    return LogReporter(analyser)


@pytest.fixture
def malformed_reporter():
    analyser = LogAnalyser()

    analyser.analyse("log_files/malformed_logs.log")

    return LogReporter(analyser)