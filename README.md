![Python](https://img.shields.io/badge/Python-3-blue)
![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)
![Status](https://img.shields.io/badge/Status-Active-success)

# Log Analyser

A Python-based command-line tool for analysing Linux authentication logs and detecting suspicious activity such as brute-force attacks, repeated failed logins, distributed user-targeting attacks, and anomalous authentication behaviour.

The project was designed to emulate a lightweight security analysis tool with a focus on clean architecture, configurable detection logic, and maintainable code structure.

---

# Features

- Detects brute-force login attacks using time-based analysis
- Identifies suspicious IP addresses with repeated failed attempts
- Detects distributed attacks targeting specific users from multiple IPs
- Identifies successful logins following previous failed attempts
- Calculates severity levels for detected threats
- Generates:
  - Interactive CLI reports
  - TXT export reports
  - Structured JSON reports
- Configurable detection thresholds and time windows
- Modular architecture with separation of concerns
- Automated unit tests for core detection logic

---

# Project Structure

```text
log-analyser/
├── app/
│   ├── interaction/
│   ├── log_analyser/
│   ├── main.py
│   └── config.py
│
├── log_files/
├── reports/
├── tests/
├── pytest.ini
└── README.md
```

---

# Architecture

The application follows a modular design to separate responsibilities across components.

## LogAnalyser

Responsible for:

- Parsing authentication log files
- Extracting structured log events
- Grouping and organising authentication attempts

The parser converts raw log entries into structured `LogEntry` objects for further analysis.

---

## LogReporter

Responsible for:

- Detection logic
- Threat analysis
- Severity classification
- Report generation
- TXT and JSON export functionality

This separation allows analysis logic to remain independent from user interaction.

---

## Interaction

Responsible for:

- Interactive CLI menus
- User input validation
- Runtime configuration handling
- Report execution flow

---

## LogEntry (dataclass)

Represents structured authentication events including:

- Username
- IP address
- Timestamp
- Authentication status

Using dataclasses improves readability and type safety across the application.

---

# Detection Logic

## Brute-Force Detection

Brute-force attacks are identified using a sliding-window time analysis approach.

### Process

1. Failed login attempts are grouped by IP address
2. Timestamps are sorted chronologically
3. A sliding time window checks for repeated attempts within a configurable period
4. Matching activity is flagged as suspicious

### Example

```text
192.168.1.10 -> 10 attempts in 8s [HIGH]
```

---

## User-Targeting Detection

Detects distributed attacks where multiple IP addresses repeatedly target the same user account.

### Example

```text
admin targeted by 12 IPs (24 attempts) [MEDIUM]
```

---

## Suspicious Success Detection

Flags IP addresses that successfully authenticate after multiple failed login attempts, which may indicate compromised credentials.

---

# Severity Levels

Detected threats are categorised into severity levels:

| Severity | Description |
|---|---|
| LOW | Minor suspicious behaviour |
| MEDIUM | Repeated or potentially malicious activity |
| HIGH | Likely active attack behaviour |

---

# Example Output

```text
=== Brute Force Detected ===

192.168.1.10 -> 10 attempts in 8s [HIGH]
10.0.0.5 -> 6 attempts in 9s [MEDIUM]

=== User Targeted Attacks Detected ===

admin targeted by 12 IPs (24 attempts) [HIGH]
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/Pixsl-Labs/Log-Analyser.git
cd Log-Analyser
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Usage

## Interactive Mode

Launch the interactive CLI menu:

```bash
python3 -m app.main <log_file>
```

Example:

```bash
python3 -m app.main brute_force.log
```

---

## Full Report Mode

Generate a complete report immediately:

```bash
python3 -m app.main <log_file> --report
```

---

# Report Exporting

## TXT Export

Exports a human-readable report:

```text
reports/report.txt
```

---

## JSON Export

Exports structured machine-readable analysis data:

```json
{
  "ip": "192.168.1.10",
  "attempts": 10,
  "severity": "HIGH"
}
```

---

# Testing

The project includes automated tests for core detection logic and severity classification.

Run all tests:

```bash
pytest
```

Example tested functionality:

- Brute-force detection
- User-targeting detection
- Severity classification
- Negative detection cases

---

# Design Goals

The project focuses on:

- Clean, readable code
- Modular architecture
- Practical cybersecurity analysis
- Configurable detection behaviour
- Maintainability and extensibility
- Real-world engineering practices

The goal was not to build a production SIEM, but to demonstrate practical software engineering and security analysis principles in a structured Python application.

---

# Why I Built This

This project was developed to improve my understanding of:

- Detection engineering
- Authentication security analysis
- Python software architecture
- Configurable security tooling
- Practical cybersecurity workflows

It also served as an opportunity to practise writing maintainable, modular code similar to real-world internal security tooling.

---

# Limitations

- Assumes Linux-style authentication logs
- Limited malformed log handling
- Detection thresholds are simplistic and heuristic-based
- No real-time monitoring
- No persistence or database integration
- No correlation across multiple log sources

---

# Future Improvements

Potential future enhancements include:

- Real-time log monitoring
- CSV export support
- Advanced anomaly detection
- Configuration files
- Improved threat scoring
- Multi-file analysis
- Improved log parsing resilience
- Dashboard or web interface
- Containerisation with Docker

---

# Technologies Used

- Python 3
- argparse
- logging
- dataclasses
- pytest
- JSON

---

# Author

Samuel Stacey

Cybersecurity and software engineering student focused on secure development, detection engineering, and practical security tooling.