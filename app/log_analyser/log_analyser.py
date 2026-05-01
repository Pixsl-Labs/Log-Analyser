import re, logging
from datetime import datetime
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

@dataclass
class LogEntry:
    ip: str
    user: str
    timestamp: datetime
    status: str

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
                print("No failed login attempts found.")
            if not found_success:
                print("No successful logins found.")

            return True

        except FileNotFoundError:
            logging.error(f"\nError: The file '{file_path}' was not found.")
            return False

    def extract_failed_ip(self, line: str) -> None:
        """
        Extracts IP address, username, and timestamp from a failed login line
        and stores the result

        Returns:
            str or None: Failed login attempts if found, otherwise None
        """
        ip_match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
        user_match = re.search(r'Failed password for (?:invalid user )?(\w+)', line)

        ip = ip_match.group() if ip_match else "unknown"
        user = user_match.group(1) if user_match else "unknown"

        timestamp = self.extract_time_stamps(line)

        if timestamp:
            dt = datetime.strptime(timestamp, "%b %d %Y %H:%M:%S")
        else:
            dt = None

        self.failed_logins.append(LogEntry(ip=ip, user=user, timestamp=dt, status="FAILED"))

        if ip_match:
            self.failed_ip_counts[ip] = self.failed_ip_counts.get(ip, 0) + 1

    def extract_successful_login(self, line: str) -> None:
        """
        Extracts IP address and username from a successful login line
        and stores the result

        Returns:
            str or None: Successful logins if found, otherwise None
        """
        line_lower = line.lower()
        ip_match = re.search(r'\b(?:from|for .*? from) ([\d\.]+)', line_lower)
        user_match = re.search(r'for (\w+)', line_lower)

        ip = ip_match.group(1) if ip_match else "unknown"
        user = user_match.group(1) if user_match else "unknown"

        self.successful_logins.append(LogEntry(ip=ip, user=user, timestamp=None, status="SUCCESS"))

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