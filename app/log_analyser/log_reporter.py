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
        for ip, user, _ in self.analyser.failed_logins:
            print(f"   User '{user}' failed login from {ip}")

    def get_successful_logins(self):
        if not self.analyser.successful_logins:
            return

        print("Successful logins:")
        for ip, user in self.analyser.successful_logins:
            print(f"   User '{user}' logged in from {ip}")

    def get_total_successful_login_attempts(self):
        total = len(self.analyser.successful_logins)
        print(f"Total number of successful logins: {total}\n")

    def get_total_number_of_unique_ip_addresses(self):
        all_ips = set()

        for ip, _, _ in self.analyser.failed_logins:
            all_ips.add(ip)

        for ip, _ in self.analyser.successful_logins:
            all_ips.add(ip)

        print(f"Number of unique IPs: {len(all_ips)}\n")

    def detect_bruteforce(self, threshold=5, window_seconds=10):
        ip_attempts = self.analyser.group_attempts_by_ip()
        results = []

        for ip, time_stamps in ip_attempts.items():
            time_stamps.sort()

            for i in range(len(time_stamps) - threshold + 1):
                start = time_stamps[i]
                end = time_stamps[i + threshold - 1]

                diff = (end - start).seconds

                if diff <= window_seconds:
                    results.append((ip, threshold, diff))
                    break
                
        return results
    
    def get_brute_force_results(self):
        results = self.detect_bruteforce()

        if not results:
            print("No brute force activity detected")
            return
        
        print("Brute force detected:\n")

        for ip, threshold, diff in results:
            print(f"   {ip} -> {threshold} attempts in {diff}s (threshold={threshold})")

    def get_most_targeted_user(self):
        user_counts = {}

        for ip, user, _ in self.analyser.failed_logins:
            user_counts[user] = user_counts.get(user, 0) + 1

        sorted_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)

        print("Most targeted users:")
        for user, count in sorted_users:
            print(f"   {user} -> {count} attempts")

    def detect_suspicious_success(self):
        failed_ips = set(ip for ip, _, _ in self.analyser.failed_logins)

        print("IPs with success after failure")
        for ip, user in self.analyser.successful_logins:
            if ip in failed_ips:
                print(f"   {ip} successfully logged in after failures")