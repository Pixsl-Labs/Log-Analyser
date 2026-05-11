import json
import os

from app.log_analyser.log_reporter import LogReporter
from app.log_analyser.log_analyser import LogAnalyser
from conftest import brute_force_reporter

def test_export_txt_creates_file(brute_force_reporter):
    output_file = "tests/test_files/test_txt_report_created.txt"

    brute_force_reporter.export_json(output_file)

    assert os.path.exists(output_file)

def test_export_json_creates_file(brute_force_reporter):
    output_file = "tests/test_files/test_json_report_created.json"

    brute_force_reporter.export_json(output_file)

    assert os.path.exists(output_file)

def test_export_json_contains_expected_keys(brute_force_reporter):
    output_file = "tests/test_files/test_report.json"

    brute_force_reporter.export_json(output_file)

    with open(output_file, "r") as file:
        data = json.load(file)

    expected_keys = {
            "generated_at",
            "summary",
            "suspicious_ips",
            "brute_force",
            "most_targeted_users",
            "user_targeting",
            "suspicious_success"
        }

    assert expected_keys.issubset(data.keys())