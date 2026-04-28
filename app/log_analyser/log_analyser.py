import re
from datetime import datetime

class LogAnalyser:
    def __init__(self):
        self.failed_logins = []
        self.successful_logins = []
        self.failed_ip_counts = {}

    def analyse(self, file_path):
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

            print(f"\nAnalysing file: {file_path}")

            if not found_failed:
                print("No failed login attempts found.")
            if not found_success:
                print("No successful logins found.")

            return True

        except FileNotFoundError:
            print(f"\nError: The file '{file_path}' was not found.")
            return False

    def extract_failed_ip(self, line):
        ip_match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
        user_match = re.search(r'Failed password for (?:invalid user )?(\w+)', line)

        ip = ip_match.group() if ip_match else "unknown"
        user = user_match.group(1) if user_match else "unknown"

        time_stamp = self.extract_time_stamps(line)

        if time_stamp:
            dt = datetime.strptime(time_stamp, "%b %d %Y %H:%M:%S")
        else:
            dt = None

        self.failed_logins.append((ip, user, dt))

        if ip_match:
            self.failed_ip_counts[ip] = self.failed_ip_counts.get(ip, 0) + 1

    def extract_successful_login(self, line):
        line_lower = line.lower()
        ip_match = re.search(r'\b(?:from|for .*? from) ([\d\.]+)', line_lower)
        user_match = re.search(r'for (\w+)', line_lower)

        ip = ip_match.group(1) if ip_match else "unknown"
        user = user_match.group(1) if user_match else "unknown"

        self.successful_logins.append((ip, user))

    def extract_time_stamps(self, line):
        match = re.search(r'^\w+\s+\d+\s+\d{4}\s+\d{2}:\d{2}:\d{2}', line)
        if match:
            return match.group()
        return None

    def group_attempts_by_ip(self):
        ip_attempts = {}

        for ip, user, time_stamp in self.failed_logins:
            if time_stamp is None:
                continue

            if ip not in ip_attempts:
                ip_attempts[ip] = []

            ip_attempts[ip].append(time_stamp)

        return ip_attempts

    def reset(self):
        self.failed_logins = []
        self.successful_logins = []
        self.failed_ip_counts = {}