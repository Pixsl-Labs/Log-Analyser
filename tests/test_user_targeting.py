from app.log_analyser.log_reporter import LogReporter
from app.log_analyser.log_analyser import LogAnalyser

def test_user_targeting_detected():
    analyser = LogAnalyser()
    analyser.analyse("log_files/combined_attack.log")

    reporter = LogReporter(analyser)

    results = reporter.get_user_targeting(5)

    assert len(results) > 0

def test_no_user_targeting_detected():
    analyser = LogAnalyser()
    analyser.analyse("log_files/empty.log")
    
    reporter = LogReporter(analyser)

    results = reporter.get_user_targeting(5)

    assert len(results) == 0