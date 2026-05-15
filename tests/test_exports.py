import json
import os

from app.log_analyser.log_reporter import LogReporter
from app.log_analyser.log_analyser import LogAnalyser
from conftest import brute_force_reporter

def test_export_txt_creates_file(brute_force_reporter):
    output_file = "tests/test_reports/test_txt_report_created.txt"

    data = brute_force_reporter.get_failed_logins()

    brute_force_reporter.export_json(
        output_file,
        "Failed Logins",
        data
    )

    assert os.path.exists(output_file)

def test_export_json_creates_file(brute_force_reporter):
    output_file = "tests/test_reports/test_json_report_created.json"

    data = brute_force_reporter.get_failed_logins()

    brute_force_reporter.export_json(
        output_file,
        "Failed Logins",
        data
    )

    assert os.path.exists(output_file)

def test_export_json_contains_expected_keys(brute_force_reporter):
    output_file = "tests/test_reports/test_report.json"

    data = brute_force_reporter.get_failed_logins()

    brute_force_reporter.export_json(
        output_file,
        "Failed Logins",
        data
    )

    with open(output_file, "r") as file:
        data = json.load(file)

    expected_keys = {
        "generated_at",
        "title",
        "results"
    }

    assert expected_keys.issubset(data.keys())