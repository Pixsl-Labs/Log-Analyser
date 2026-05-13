from app.log_analyser.log_entry import LogEntry
from app.config import SEVERITY_LEVEL

import re, logging
from datetime import datetime

class LogAnalyser:
    """
    Analyses authentication log files to extract information about
    failed and successful login attempts.

    Tracks:
    - Failed login attempts (IP, user, timestamp)
    - Successful logins
    - Failed login counts per IP
    """
    def __init__(self):
        self.failed_logins: list[LogEntry] = []
        self.successful_logins: list[LogEntry] = []
        self.failed_ip_counts = {}

    def get_severity_level(self, count: int) -> str:
        """
        Returns the severity level based on the number of attempts.

        Args:
            count (int): Number of detected attempts.

        Returns:
            str: Severity level
        """
        if count >= SEVERITY_LEVEL["HIGH"]:
            return "HIGH"

        elif count >= SEVERITY_LEVEL["MEDIUM"]:
            return "MEDIUM"

        else:
            return "LOW"

    def analyse(self, file_path: str) -> bool:
        """
        Reads and processes a log file, extracting failed and successful
        login attempts

        Returns:
            bool: True if file was successfully processed, False otherwise
        """
        found_failed = False
        found_success = False

        try:
            with open(file_path, 'r') as file:
                for line in file:
                    if "failed password" in line.lower():
                        found_failed = True
                        self.extract_failed_ip(line)
                    elif "accepted password" in line.lower() or "session opened" in line.lower():
                        found_success = True
                        self.extract_successful_login(line)

            logging.info(f"Analysing file: {file_path}")

            if not found_failed: 
                print("\nNo failed login attempts found.")
            if not found_success:
                print("\nNo successful logins found.")

            return True

        except FileNotFoundError:
            logging.error(f"Error: The file '{file_path}' was not found.")
            return False

    def extract_failed_ip(self, line):
        """
        Extracts IP address, username, and timestamp from a failed login line
        and stores the result.
        """
        ip_match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
        user_match = re.search(r'Failed password for (?:invalid user )?(\w+)', line)

        if not ip_match:
            print()
            logging.warning(f"Skipping failed login line with missing IP: {line.strip()}\n")
            return

        ip = ip_match.group()
        user = user_match.group(1) if user_match else "unknown"

        timestamp = self.extract_time_stamps(line)

        if not timestamp:
            logging.warning(f"Skipping failed login line with missing timestamp: {line.strip()}\n")
            return

        try:
            dt = datetime.strptime(timestamp, "%b %d %Y %H:%M:%S")
        except ValueError:
            logging.warning(f"Skipping failed login line with invalid timestamp: {line.strip()}\n")
            return

        self.failed_logins.append(
            LogEntry(ip=ip, user=user, timestamp=dt, status="FAILED")
        )

        self.failed_ip_counts[ip] = (
            self.failed_ip_counts.get(ip, 0) + 1
        )

        attempts = self.failed_ip_counts[ip]

        severity = self.get_severity_level(attempts)

        self.failed_logins[-1].severity = severity

    def extract_successful_login(self, line):
        """
        Extracts IP address and username from a successful login line
        and stores the result.
        """
        line_lower = line.lower()

        ip_match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line_lower)
        user_match = re.search(r'for (\w+)', line_lower)

        if not ip_match:
            logging.warning(f"Skipping successful login line with missing IP: {line.strip()}\n")
            return

        ip = ip_match.group()
        user = user_match.group(1) if user_match else "unknown"

        timestamp = self.extract_time_stamps(line)

        dt = None

        if timestamp:
            try:
                dt = datetime.strptime(timestamp, "%b %d %Y %H:%M:%S")
            except ValueError:
                logging.warning(f"Successful login has invalid timestamp, storing without timestamp: {line.strip()}\n")

        self.successful_logins.append(
            LogEntry(ip=ip, user=user, timestamp=dt, status="SUCCESS")
        )

    def extract_time_stamps(self, line: str) -> str | None:
        """
        Extracts the timestamp from a log line.

        Returns:
            str or None: The timestamp string if found, otherwise None
        """
        match = re.search(r'^\w+\s+\d+\s+\d{4}\s+\d{2}:\d{2}:\d{2}', line)
        if match:
            return match.group()
        return None

    def group_attempts_by_ip(self) -> dict[str, list[datetime]]:
        """
        Groups failed login timestamps by IP address

        Returns:
            dict: {ip: [timestamps]}
        """
        ip_attempts = {}

        for entry in self.failed_logins:
            if entry.timestamp is None:
                continue

            if entry.ip not in ip_attempts:
                ip_attempts[entry.ip] = []

            ip_attempts[entry.ip].append(entry.timestamp)

        return ip_attempts

    def reset(self) -> None:
        """
        Clears all stored login data to allow analysis of a new file

        Returns:
            None
        """
        self.failed_logins = []
        self.successful_logins = []
        self.failed_ip_counts = {}