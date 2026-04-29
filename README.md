# Log Analyser

A command-line tool for analysing authentication log files to identify suspicious activity, including failed login attempts, brute-force attacks, and anomalous login behaviour.

The application processes log files and provides both high-level summaries and detailed insights into login activity.

## Features

- Detect failed login attempts
- Identify suspicious IP addresses based on failed login frequency
- Detect brute-force attacks using time-based analysis
- Identify the most targeted user accounts
- Detect successful logins following multiple failed attempts
- Display total and unique login statistics
- Export analysis reports to a `.txt` file with a custom filename
- Interactive command-line interface with selectable report options

## Getting Started

### 1. Clone the repository

```
git clone https://github.com/Pixsl-Labs/Log-Analyser.git

cd Log-Analyser
```

### 2. Create and activate a virtual environment

```
python -m venv venv
```

Windows:

```
venv\Scripts\activate
```

Linux / macOS:

```
source venv/bin/activate
```

### 3. Install dependencies

```
pip install -r requirements.txt
```

### 4. Run the application

```
python -m app.main <log_file>
```

Alternatively, the program can be run directly through an IDE using a configured run profile.

## Usage

Upon running the application, the user is prompted to select options from an interactive menu:

```
--- Log Analysis Menu ---

1. Show full report
2. Show total failed logins
3. Show suspicious IPs
4. Show failed login details
5. Show successful logins
6. Show unique IP count
7. Show brute force detection
8. Show targeted users
9. Show suspicious success
10. Export report to file
11. Analyse new file
12. Exit
```

The tool provides the following insights:

- Total number of unique IP addresses
- Total number of failed login attempts
- Suspicious IPs with associated attempt counts and risk levels
- Detailed list of failed login attempts (user and IP)
- Total number of successful logins
- Detailed list of successful login events
- Detection of brute-force attacks based on configurable thresholds
- Identification of the most targeted user accounts
- Detection of IPs that successfully authenticate after repeated failures
- Ability to export a structured report to a text file

## Goal

To analyse system authentication logs and detect potentially malicious behaviour, such as repeated failed login attempts and brute-force attacks, in a structured and accessible way.

## Future Improvements

- Extend detection capabilities towards a SOC-style monitoring tool
- Add support for additional log formats
- Export reports in structured formats (e.g. JSON)
- Introduce configurable thresholds via external configuration
- Improve visual formatting of reports

## References

https://www.codecademy.com/article/command-line-arguments-in-python