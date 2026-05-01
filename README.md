# Log Analyser

A Python-based command-line tool for analysing authentication log files and detecting suspicious activity such as brute-force attacks, repeated failed logins, and anomalous login behaviour.

The tool is designed with a modular architecture, separating log parsing, analysis, and interaction layers, and supports both interactive exploration and automated command-line usage.

## Usage Modes

The application supports two modes of operation:

### 1. Command-Line Mode (Recommended)

Run a full report directly from the terminal:

```
python3 -m app.main <log_file> --report
```

This executes the analysis immediately without launching the interactive menu.

---

### 2. Interactive Mode

Run without the `--report` flag to access the menu interface:

```
python3 -m app.main <log_file>
```

This allows step-by-step exploration of the log data.

## Architecture

The project follows a modular design to separate concerns:

- **LogAnalyser**
  - Responsible for parsing raw log files
  - Converts log entries into structured `LogEntry` objects

- **LogReporter**
  - Performs analysis on parsed data
  - Detects suspicious behaviour and generates reports

- **Interaction**
  - Provides a command-line interface for user interaction

- **LogEntry (dataclass)**
  - Represents a structured log event (IP, user, timestamp, status)

This separation improves readability, maintainability, and extensibility of the system.

## Detection Logic

### Brute-Force Detection

Brute-force attacks are detected using a time-based approach:

- Failed login attempts are grouped by IP address
- Attempts are sorted by timestamp
- A sliding window is applied to identify multiple attempts within a short time frame
- If the number of attempts exceeds a configured threshold within the time window, the IP is flagged as suspicious

### Suspicious Success Detection

The tool identifies IP addresses that successfully authenticate after previous failed attempts, which may indicate compromised credentials.

## Limitations

- Assumes standard Linux authentication log format (e.g. `/var/log/auth.log`)
- Limited handling of malformed or incomplete log entries
- Detection thresholds are static and may require tuning for different environments
- Does not currently support real-time log monitoring

## Future Improvements

- Add real-time log monitoring capabilities
- Introduce structured output formats (JSON, CSV)
- Implement configurable thresholds via external configuration files
- Add unit testing for detection logic
- Improve CLI with additional flags and filtering options
- Integrate logging framework for better observability