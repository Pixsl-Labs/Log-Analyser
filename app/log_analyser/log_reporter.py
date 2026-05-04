from app.log_analyser.log_analyser import LogAnalyser
from app.config import MAX_ATTEMPTS, TIME_WINDOW_SECONDS

import json
from collections import defaultdict

class LogReporter:
    """
    Generates reports and summaries based on analysed log data.

    Responsible for:
    - Displaying login statistics
    - Detecting suspicious activity
    - Exporting reports to file
    """
    def __init__(self, analyser):
        self.analyser: LogAnalyser = analyser

    def get_total_failed_login_attempts(self) -> int:
        """
        Returns the total number of failed logins detected

        Returns:
            int: Total number of failed login attempts
        """
        return sum(self.analyser.failed_ip_counts.values())
    
    def get_risk_level(self, count: int) -> str:
        """
        Returns the risk level based on the number of attempts

        Returns:
            str: Risk level
        """
        return "Investigate" if count >= MAX_ATTEMPTS else "Low risk"

    def print_suspicious_ips(self) -> None:
        """
        Prints suspicious IP addresses due to failed login attempts
        Showing the IP address, number of attempts and severity level

        Returns:
            None
        """
        if not self.analyser.failed_ip_counts:
            print("No suspicious IPs found.")
            return

        print("\n=== Suspicious IPs (Failed Attempts) ===")
        sorted_ips = sorted(self.analyser.failed_ip_counts.items(), key=lambda x: x[1], reverse=True)

        for ip, count in sorted_ips:
            status = self.get_risk_level(count)
            print(f"   {ip} -> {count} attempts ({status})")

    def print_failed_logins(self) -> None:
        """
        Prints failed login attempts
        
        Returns:
            None
        """
        if not self.analyser.failed_logins:
            print("No failed logins found.")
            return

        print("\n=== Failed Logins ===")
        for entry in self.analyser.failed_logins:
            print(f"   User '{entry.user}' failed login from {entry.ip}")

    def print_successful_logins(self) -> None:
        """
        Prints successful logins

        Returns:
            None
        """
        if not self.analyser.successful_logins:
            print("No successful logins found.")
            return

        print("\n=== Successful Logins ===")
        for entry in self.analyser.successful_logins:
            print(f"   User '{entry.user}' logged in from {entry.ip}")

    def get_total_successful_logins(self) -> int:
        """
        Returns the total number of successful logins

        Returns:
            int: Total number of successful logins
        """
        return len(self.analyser.successful_logins)

    def get_total_number_of_unique_ip_addresses(self) -> int:
        """
        Returns the total number of unique IP addresses detected

        Returns:
            int: Total number of unqiue IP addresses identified
        """
        all_ips = set()

        for entry in self.analyser.failed_logins:
            all_ips.add(entry.ip)

        for entry in self.analyser.successful_logins:
            all_ips.add(entry.ip)

        return len(all_ips)

    def detect_bruteforce(self) -> list[tuple[str, int, float]]:
        """
        Detects brute force attacks based on failed login attempts
        within a specified time window

        Returns:
            list[tuple[str, int, float]]: List of (ip, attempts, time_window_seconds)
        """
        threshold = MAX_ATTEMPTS
        window_seconds = TIME_WINDOW_SECONDS
        ip_attempts = self.analyser.group_attempts_by_ip()
        results = []

        for ip, time_stamps in ip_attempts.items():
            time_stamps.sort()

            for i in range(len(time_stamps) - threshold + 1):
                start = time_stamps[i]
                end = time_stamps[i + threshold - 1]

                diff = (end - start).total_seconds()

                if diff <= window_seconds:
                    results.append((ip, threshold, diff))
                    break
                
        return results
    
    def print_brute_force_results(self) -> None:
        """
        Prints the IP addresses of brute force attempts
        with the number of attempts within a specified time window

        Returns:
            None
        """
        threshold = MAX_ATTEMPTS
        results = self.detect_bruteforce()

        if not results:
            print("No brute force activity detected")
            return
        
        print("\n=== Brute Force Detected ===")

        for ip, threshold, diff in results:
            print(f"   {ip} -> {threshold} attempts in {diff}s (threshold={threshold})")

    def get_most_targeted_users(self) -> list[tuple[str, int]]:
        """
        Counts failed login attempts per user and returns a list
        of users sorted by number of attempts (descending)

        Returns:
            list[tuple[str, int]]: List of (user, attempt_count)
        """
        user_counts = {}

        for entry in self.analyser.failed_logins:
            user_counts[entry.user] = user_counts.get(entry.user, 0) + 1

        sorted_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)

        return sorted_users

    def print_most_targeted_user(self) -> None:
        """
        Prints out the most targeted users

        Returns:
            None
        """
        sorted_users = self.get_most_targeted_users()

        if not sorted_users:
            print("No targeted users found.")
            return

        print("\n=== Most Targeted Users ===")
        for user, count in sorted_users:
            print(f"   {user} -> {count} attempts")

    def detect_suspicious_success(self) -> None:
        """
        Detects any suspicious login which had previous failed login attempts

        Returns:
            None
        """
        failed_ips = set(entry.ip for entry in self.analyser.failed_logins)

        found = False

        for entry in self.analyser.successful_logins:
            if entry.ip in failed_ips:
                if not found:
                    print("\n=== IPs with Success After Failure ===")
                    found = True
                print(f"   {entry.ip} successfully logged in after failures")

        if not found:
            print("No suspicious success detected.")

    def detect_user_targeting(self, threshold=5):
        """
        Detects users being targeted by multiple IPs.

        Returns:
            List of tuples (user, unique_ips, total_attempts)
        """
        user_attempts = defaultdict(list)

        for entry in self.analyser.failed_logins:
            user_attempts[entry.user].append(entry.ip)

        results = []

        for user, ips in user_attempts.items():
            unique_ips = set(ips)

            if len(unique_ips) >= threshold:
                results.append((user, len(unique_ips), len(ips)))

        return results
    
    def print_user_targeting(self):
        """
        Prints results of users being targeted by multiple IPs.
        """
        results = self.detect_user_targeting()

        if not results:
            print("No user-targeted attacks detected.")
            return
        
        print("\n=== User Targeted Attacks Detected ===")

        for user, unique_ips, total_attempts in results:
            print(f"   {user} targeted by {unique_ips}, IPs ({total_attempts}) attempts")

    def print_attack_summary(self) -> None:
        """
        Prints a high-level sumamry of detected threats.
        """
        print("\n--- Attack Summary ---\n")

        # Total failed attempts
        total_failed = self.get_total_failed_login_attempts()
        print(f"Total failed attempts: {total_failed}")

        # Top IP
        if self.analyser.failed_logins:
            top_ip = max(self.analyser.failed_ip_counts.items(), key=lambda x: x[1])
            print(f"Top attacking IP: {top_ip[0]} ({top_ip[1]} attempts)")
        else:
            print("Top attacking IP: None")

        # Top user
        targeted = self.get_most_targeted_users()
        if targeted:
            print(f"Most targeted user: {targeted[0]}, {targeted[1]}")
        else:
            print("Most targeted user: None")

        # Brute-force count
        brute = self.detect_bruteforce()
        print(f"Brute-force alerts: {len(brute)}")

        # Distributed attack count
        targeting = self.detect_user_targeting()
        print(f"User-targeting alerts: {len(targeting)}")

    def export_txt(self, filename: str) -> None:
        """
        Exports a full report based on the .log file provided with a custom
        filename (*.txt)

        Returns:
            None
        """
        threshold = MAX_ATTEMPTS
        with open(filename, "w") as f:
            f.write("--- Log Analysis Report ---\n\n")

            if not self.analyser.failed_logins and not self.analyser.successful_logins:
                f.write("Log file contained no relevant login activity.\n\n")
            
            f.write("!!! Attention Needed !!!\n\n")

            # Unique IPs
            total_ips = self.get_total_number_of_unique_ip_addresses()
            f.write(f"Unique IPs: {total_ips}\n\n")

            # Suspicious IPs
            if self.analyser.failed_ip_counts:
                sorted_ips = sorted(self.analyser.failed_ip_counts.items(), key=lambda x: x[1], reverse=True)
                f.write("=== Suspicious IPs (Failed Attempts) ===\n")
                
                for ip, count in sorted_ips:
                    status = self.get_risk_level(count)
                    f.write(f"   {ip:<15} -> {count} attempts ({status})\n")

                f.write("\n")
            else:
                f.write("No suspicious IPs found.\n")
            
            # Failed Logins
            if self.analyser.failed_logins:
                f.write("=== Failed Logins ===\n")
                for entry in self.analyser.failed_logins:
                    f.write(f"   User '{entry.user}' failed login from {entry.ip}\n")

                f.write("\n")
            else:
                f.write("No failed logins found.\n")

            # Brute-force results
            results = self.detect_bruteforce()
            if results:
                f.write("=== Brute Force Detection ===\n")

                for ip, threshold, diff in results:
                    f.write(f"   {ip} -> {threshold} attempts in {diff}s (threshold={threshold})\n")
            else:
                f.write("No brute force detected\n")

            # Most Targeted users
            sorted_users = self.get_most_targeted_users()

            if sorted_users:
                f.write("\n=== Most Targeted Users ===\n")
                
                for user, count in sorted_users:
                    f.write(f"   {user:<10} -> {count} attempts\n")
            else:
                f.write("\nNo targeted users found.\n")

            # Suspicious success
            failed_ips = set(entry.ip for entry in self.analyser.failed_logins)
            found = False

            for entry in self.analyser.successful_logins:
                if entry.ip in failed_ips:
                    if not found:
                        f.write("\n=== IPs with Success After Failure ===\n")
                        found = True
                    f.write(f"   {entry.ip} successfully logged in after failures\n")

            if not found:
                f.write("No suspicious success detected.\n")

            # User-targeting by multiple IPs
            targeted_users = self.detect_user_targeting()
            f.write("\n=== User Targeted Attacks Detected ===\n")

            for user, unique_ips, total_attempts in targeted_users:
                f.write(f"   {user} targeted by {unique_ips} IPs ({total_attempts} attempts)")

            f.write("\n\n--- Standard Logins ---\n\n")

            # Total Successful login attempts
            total_ = self.get_total_successful_logins()
            f.write(f"Total number of successful logins: {total_}\n")

            # Successful logins
            if self.analyser.successful_logins:
                f.write("\n=== Successful Logins ===\n")
                for entry in self.analyser.successful_logins:
                    f.write(f"   User '{entry.user}' logged in from {entry.ip}\n")
            else:
                f.write("\nNo successful logins found.\n")

    def export_json(self, filename: str) -> None:
        """
        Exports analysis results in structured JSON format.
        """

        data = {
            "summary": {
                "total_failed": self.get_total_failed_login_attempts(),
                "total_successful": self.get_total_successful_logins(),
                "unique_ips": self.get_total_number_of_unique_ip_addresses()
            },
            "suspicious_ips": [
                {"ip": ip, "attempts": count}
                for ip, count in self.analyser.failed_ip_counts.items()
            ],
            "brute_force": [
                {
                    "ip": ip,
                    "attempts": attempts,
                    "time_window_seconds": diff
                }
                for ip, attempts, diff in self.detect_bruteforce()
            ],
            "most_targeted_users": [
                {"user": user, "attempts": count}
                for user, count in self.get_most_targeted_users()
            ],
            "user_targeting": [
                {
                    "user": user,
                    "unique_ips": unique_ips,
                    "total_attempts": total
                }
                for user, unique_ips, total in self.detect_user_targeting()
            ],
            "suspicious_success": [
                entry.ip
                for entry in self.analyser.successful_logins
                if entry.ip in {e.ip for e in self.analyser.failed_logins}
            ]
        }

        with open(filename, "w") as f:
            json.dump(data, f, indent=4)

        print(f"JSON report exported to {filename}")