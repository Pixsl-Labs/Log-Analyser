from app.log_analyser.log_analyser import LogAnalyser
from app.config import MAX_ATTEMPTS

class LogReporter:
    def __init__(self, analyser):
        self.analyser: LogAnalyser = analyser

    def get_total_failed_login_attempts(self):
        total = sum(self.analyser.failed_ip_counts.values())
        print(f"Total number of failed logins: {total}")

    def get_suspicious_ips(self):
        if not self.analyser.failed_ip_counts:
            return

        sorted_ips = sorted(self.analyser.failed_ip_counts.items(), key=lambda x: x[1], reverse=True)

        print("Suspicious IPs (failed attempts):")
        for ip, count in sorted_ips:
            status = "Investigate" if count >= MAX_ATTEMPTS else "Low risk"
            print(f"   {ip} -> {count} attempts ({status})")

    def get_failed_logins(self):
        if not self.analyser.failed_logins:
            return

        print("Failed logins:")
        for ip, user in self.analyser.failed_logins:
            print(f"   User '{user}' failed login from {ip}")

    def get_successful_logins(self):
        if not self.analyser.successful_logins:
            return

        print("Successful logins:")
        for ip, user in self.analyser.successful_logins:
            print(f"   User '{user}' logged in from {ip}")

    def get_total_successful_login_attempts(self):
        total = len(self.analyser.successful_logins)
        print(f"Total number of successful logins: {total}")

    def get_total_number_of_unique_ip_addresses(self):
        all_ips = set(ip for ip, _ in self.analyser.failed_logins + self.analyser.successful_logins)
        print(f"Number of unique IPs: {len(all_ips)}")