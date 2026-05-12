from app.log_analyser.log_analyser import LogAnalyser, LogEntry
from app.config import MAX_ATTEMPTS, TIME_WINDOW_SECONDS, SEVERITY_LEVEL 

import json
from collections import defaultdict
from datetime import datetime

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
    
    def get_failed_logins_by_user(self, username: str) -> list:
        """
        Returns all failed login attempts for a specific user.
        
        Args:
            username (str): Username to filter by
            
        Returns:
            list: Matching failed login entries
        """

        results = []

        for entry in self.analyser.failed_logins:
            if entry.user.lower() == username.lower():
                results.append(entry)

        return results
    
    def get_failed_logins_by_ip(self, ip: str) -> list:
        """
        Returns all failed login attempts for a specific IP address.
        
        Args:
            ip (str): IP address to filter by
            
        Returns:
            list: Matching failed login entries
        """

        results = []

        for entry in self.analyser.failed_logins:
            if entry.ip == ip:
                results.append(entry)

        return results
    
    def print_failed_logins_by_ip(self, ip: str) -> None:
        """
        Prints failed login attempts for a specific IP address.
        
        Args:
            ip (str): IP address to filter by
            
        Returns:
            None
        """

        results = self.get_failed_logins_by_ip(ip)

        if not results:
            print(f"\nNo failed logins found for IP '{ip}'.")
            return
        
        print(f"\n=== Failed Logins for IP: {ip} ===")

        print(f"\n   Total failed attempts: {len(results)}\n")

        for entry in results:
            print(f"   {entry.user} failed login from {entry.ip}")
    
    def print_failed_logins_by_user(self, username: str) -> None:
        """
        Prints failed login attempts for a specific user.
        
        Args:
            username (str): Username to filter by
            
        Returns:
            None
        """

        results = self.get_failed_logins_by_user(username)

        if not results:
            print(f"\nNo failed logins found for user '{username}'.")
            return
        
        print(f"\n=== Failed Logins for User: {username} ===")

        print(f"\n   Total failed attempts: {len(results)}\n")

        for entry in results:
            print(f"   {entry.user} failed login from {entry.ip}")
    
    def get_risk_level(self, count: int) -> str:
        """
        Returns the risk level based on the number of attempts

        Returns:
            str: Risk level
        """
        return "Investigate" if count >= MAX_ATTEMPTS else "Low risk"
    
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
        
    def get_total_suspicious_ips(self) -> int:
        """
        Returns the total number of suspicious IPs detected.
        
        Returns:
            int: Total number of suspicious IPs
        """
        return len(self.analyser.failed_ip_counts)
    
    def get_activity_by_ip(self, ip: str) -> list:
        """
        Returns all login activity associated with a specific IP address.
        
        Args:
            ip (str): IP address to investigate
            
        Returns:
            list: Matching login entries
        """

        results = []

        for entry in self.analyser.failed_logins:
            if entry.ip == ip:
                results.append(entry)

        for entry in self.analyser.successful_logins:
            if entry.ip == ip:
                results.append(entry)

        return results
    
    def get_activity_by_username(self, username: str) -> list:
        """
        Returns all login activity associated with a specific username.
        
        Args:
            username (str): Username to investigate
            
        Returns:
            list: Matching login entries
        """

        results = []

        for entry in self.analyser.failed_logins:
            if entry.user.lower() == username.lower():
                results.append(entry)

        for entry in self.analyser.successful_logins:
            if entry.user.lower() == username.lower():
                results.append(entry)

        return results
    
    def print_suspicious_activity_by_ip(self, ip: str) -> None:
        """
        Prints all login activity associated with a specific IP address.
        
        Returns:
            None
        """

        results = self.get_activity_by_ip(ip)

        if not results:
            print(f"\nNo activity found for IP '{ip}'")
            return
        
        print(f"\n=== Activity For IP: {ip} ===")
        
        print(f"\n   Total events: {len(results)}\n")

        for entry in results:
            print(
                f"   [{entry.status}] User '{entry.user}' "
                f"at {entry.timestamp}"
            ) 

    def print_suspicious_activity_by_username(self, username: str) -> None:
        """
        Prints all login activity associated with a specific user.
        
        Returns:
            None
        """

        results = self.get_activity_by_username(username)

        if not results:
            print(f"\nNo activity found for user '{username}'")
            return
        
        print(f"\n=== Activity For User: {username} ===")
        
        print(f"\n   Total events: {len(results)}\n")

        for entry in results:
            print(
                f"   [{entry.status}] User '{entry.user}' "
                f"at {entry.timestamp}"
            )

    def print_suspicious_ips(self) -> None:
        """
        Prints suspicious IP addresses due to failed login attempts
        Showing the IP address, number of attempts and severity level

        Returns:
            None
        """
        if not self.analyser.failed_ip_counts:
            print("\nNo suspicious IPs found.")
            return

        print("\n=== Suspicious IPs (Failed Attempts) ===\n")
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
            print("\nNo failed logins found.")
            return

        print("\n=== Failed Logins ===\n")
        for entry in self.analyser.failed_logins:
            print(f"   User '{entry.user}' failed login from {entry.ip}")

    def print_successful_logins(self) -> None:
        """
        Prints successful logins

        Returns:
            None
        """
        if not self.analyser.successful_logins:
            print("\nNo successful logins found.")
            return

        print("\n=== Successful Logins ===\n")
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

    def detect_bruteforce(
            self,
            threshold=MAX_ATTEMPTS, 
            window_seconds=TIME_WINDOW_SECONDS
        ) -> list[tuple[str, int, float]]:
        """
        Detects brute force attacks based on failed login attempts
        within a specified time window

        Returns:
            list[tuple[str, int, float]]: List of (ip, attempts, time_window_seconds)
        """
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
    
    def print_brute_force_results(
            self, 
            threshold=MAX_ATTEMPTS,
            window_seconds=TIME_WINDOW_SECONDS
        ) -> None:
        """
        Prints the IP addresses of brute force attempts
        with the number of attempts within a specified time window

        Returns:
            None
        """
        results = self.detect_bruteforce(threshold, window_seconds)

        if not results:
            print("\nNo brute force activity detected")
            return
        
        print("\n=== Brute Force Detected ===\n")

        for ip, attempts, diff in results:
            severity = self.get_severity_level(attempts)
            print(f"   {ip} -> {attempts} attempts in {diff}s (threshold={threshold}) [{severity}]")

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
            print("\nNo targeted users found.")
            return

        print("\n=== Most Targeted Users ===\n")
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
                    print("\n=== IPs with Success After Failure ===\n")
                    found = True
                print(f"   {entry.ip} successfully logged in after failures")

        if not found:
            print("\nNo suspicious success detected.")

    def detect_user_targeting(self, threshold=MAX_ATTEMPTS):
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
    
    def print_user_targeting(
            self, 
            threshold=MAX_ATTEMPTS
        ) -> None:
        """
        Prints results of users being targeted by multiple IPs.

        Returns:
            None
        """
        results = self.detect_user_targeting(threshold)

        if not results:
            print("\nNo user-targeted attacks detected.")
            return
        
        print("\n=== User Targeted Attacks Detected ===\n")

        for user, unique_ips, total_attempts in results:
            severity = self.get_severity_level(unique_ips)
            print(f"   {user} targeted by {unique_ips} IPs ({total_attempts}) attempts [{severity}]")

    def print_attack_summary(self) -> None:
        """
        Prints a high-level summary of detected threats.
        """
        print("\n=== Attack Summary ===\n")

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
            top_user, attempts = targeted[0]
            print(f"Most targeted user: {top_user} ({attempts} attempts)")
        else:
            print("Most targeted user: None")

        # Brute-force count
        brute = self.detect_bruteforce()
        print(f"Brute-force alerts: {len(brute)}")

        # Distributed attack count
        targeting = self.detect_user_targeting(MAX_ATTEMPTS)
        print(f"User-targeting alerts: {len(targeting)}")

    def export_txt(self, filename: str) -> None:
        """
        Exports a full report based on the .log file provided with a custom
        filename (*.txt)

        Returns:
            None
        """
        now = datetime.now()
        with open(filename, "w") as f:
            f.write("=== Log Analysis Report ===\n\n")
            
            f.write(now.strftime("Generated: %Y-%m-%d %H:%M:%S\n\n"))

            if not self.analyser.failed_logins and not self.analyser.successful_logins:
                f.write("Log file contained no relevant login activity.\n\n")
            
            f.write("=== Attention Needed ===\n\n")

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
                f.write("\nNo suspicious IPs found.\n")
            
            # Failed Logins
            if self.analyser.failed_logins:
                f.write("=== Failed Logins ===\n")
                for entry in self.analyser.failed_logins:
                    f.write(f"   User '{entry.user}' failed login from {entry.ip}\n")

                f.write("\n")
            else:
                f.write("\nNo failed logins found.\n")

            # Brute-force results
            results = self.detect_bruteforce()
            if results:
                f.write("=== Brute Force Detection ===\n")

                for ip, attempts, diff in results:
                    severity = self.get_severity_level(attempts)
                    f.write(f"   {ip} -> {attempts} attempts in {diff}s (threshold={MAX_ATTEMPTS}) [{severity}]\n")
            else:
                f.write("\nNo brute force detected\n")

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
                f.write("\nNo suspicious success detected.\n")

            # User-targeting by multiple IPs
            targeted_users = self.detect_user_targeting()
            f.write("\n=== User Targeted Attacks Detected ===\n")

            for user, unique_ips, total_attempts in targeted_users:
                severity = self.get_severity_level(unique_ips)
                f.write(f"   {user} targeted by {unique_ips} IPs ({total_attempts} attempts) [{severity}]\n")

            f.write("\n\n=== Standard Logins ===\n\n")

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
        now = datetime.now()

        data = {
            "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),

            "summary": self.get_attack_statistics(),

            "suspicious_ips": [
                {"ip": ip, "attempts": count}
                for ip, count in self.analyser.failed_ip_counts.items()
            ],
            "brute_force": [
                {
                    "ip": ip,
                    "attempts": attempts,
                    "time_window_seconds": round(diff, 2),
                    "severity": self.get_severity_level(attempts)
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
                    "total_attempts": total,
                    "severity": self.get_severity_level(unique_ips)
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

    def get_attack_statistics(self) -> dict:
        """
        Returns a high-level summary of attack statistics.

        Returns:
            dict: Summary statistics for analysed log data
        """

        # Failed attempts
        total_failed = self.get_total_failed_login_attempts()

        # Successful logins
        total_successful = self.get_total_successful_logins()

        # Suspicious IPs
        total_suspicious_ips = self.get_total_suspicious_ips()

        # Brute-force attempts
        total_brute_force = len(self.detect_bruteforce())

        # Number of targeted user
        total_targeted_users = len(self.get_most_targeted_users())

        # Highest severity
        highest_severity = "NONE"

        if self.analyser.failed_ip_counts:
            highest_attempts = max(self.analyser.failed_ip_counts.values())
            highest_severity = self.get_severity_level(highest_attempts)

        # Top attacker
        top_attacker = None
        if self.analyser.failed_ip_counts:
            top_ip, attempts = max(
                self.analyser.failed_ip_counts.items(),
                key=lambda x: x[1]
            )

            top_attacker = f"{top_ip} ({attempts} attempts)"
        
        # Most targeted user
        most_targeted_user = None

        targeted_users = self.get_most_targeted_users()

        if targeted_users:
            top_user, attempts = targeted_users[0]
            most_targeted_user = f"{top_user} ({attempts} attempts)"

        return {
            "failed_attempts": total_failed,
            "successful_logins": total_successful,
            "suspicious_ips": total_suspicious_ips,
            "brute_force_alerts": total_brute_force,
            "targeted_users": total_targeted_users,
            "highest_severity": highest_severity,
            "top_attacker": top_attacker,
            "most_targeted_user": most_targeted_user
        }

    def print_attack_statistics(self):
        """
        Prints a high-level summary of detected attack statistics.
        """

        stats = self.get_attack_statistics()

        print("\n=== Attack Statistics ===\n")

        print(f"\nFailed attempts: {stats['failed_attempts']}")
        print(f"\nSuccessful logins: {stats['successful_logins']}")
        print(f"\nSuspicious IPs: {stats['suspicious_ips']}")
        print(f"\nBrute-force alerts: {stats['brute_force_alerts']}")
        print(f"\nTargeted users: {stats['targeted_users']}")
        print(f"\nHighest severity: {stats['highest_severity']}")
        print(f"\nTop attacker: {stats['top_attacker']}")
        print(f"\nMost targeted user: {stats['most_targeted_user']}")

    def print_analysis_summary(self):
        stats = self.get_attack_statistics()

        print("\n=== Analysis Summary ===")

        print(f"\nFailed attempts: {stats['failed_attempts']}")
        print(f"Successful logins: {stats['successful_logins']}")
        print(f"Suspicious IPs: {stats['suspicious_ips']}")
        print(f"Brute-force alerts: {stats['brute_force_alerts']}")

    def get_activity_timeline(self) -> list[LogEntry]:
        """
        Returns all login activity sorted chronologically.
        
        Returns:
            list[LogEntry]: Login activity sorted by timestamp
        """

        all_activity = (
            self.analyser.failed_logins
            + self.analyser.successful_logins
        )

        return sorted(
            all_activity,
            key=lambda entry: entry.timestamp or datetime.min
        )
    
    def print_activity_timeline(self) -> None:
        """
        Prints a chronological activity timeline.
        
        Returns:
            None
        """
        
        timeline = self.get_activity_timeline()

        if not timeline:
            print("\nNo timeline recovered.")
            return

        print("\n=== Activity Timeline ===\n")

        for entry in timeline:
            time_str = (
                entry.timestamp.strftime("%H:%M:%S")
                if entry.timestamp
                else "Unknown"
            )

            print(
                f"   [{entry.status}] "
                f"{time_str} "
                f"{entry.user} from {entry.ip}"
            )

    def get_activity_timeline_by_user(self, username: str) -> list[LogEntry]:
        """
        Returns all login activity for a specific user sorted chronologically.
        
        Args:
            username (str): Username to filter by.
        
        Returns:
            list[LogEntry]: Login activity for the user sorted by timestamp.
        """

        timeline = self.get_activity_timeline()

        return [
            entry for entry in timeline
            if entry.user.lower() == username.lower()
        ]
    
    def print_activity_timeline_by_user(self, username: str) -> None:
        """
        Prints all login activity for a specific user sorted chronologically.

        Args:
            username (str): Username to filter by.

        Returns:
            None
        """

        timeline = self.get_activity_timeline_by_user(username)

        if not timeline:
            print(f"\nNo timeline recovered for user '{username}'.")
            return

        print(f"\n=== Activity Timeline for User: {username} ===\n")

        for entry in timeline:
            time_str = (
                entry.timestamp.strftime("%H:%M:%S")
                if entry.timestamp
                else "Unknown"
            )

            print(
                f"   [{entry.status}] "
                f"{time_str} "
                f"{entry.user} from {entry.ip}"
            )

    def print_all_usernames(self) -> None:
        """
        Prints all unique usernames.
        
        Returns:
            None
        """

        timeline = self.get_activity_timeline()

        unique_usernames = {
            entry.user
            for entry in timeline
        }

        if not unique_usernames:
            print("\nNo usernames found.")
            return

        print("\n=== All Available Users ===\n")

        for user in sorted(unique_usernames):
            print(f"   {user}")

    def get_activity_timeline_by_ip(self, ip: str) -> list[LogEntry]:
        """
        Returns all login activity for a specific IP sorted chronologically.
        
        Args:
            ip (str): IP address to filter by.
        
        Returns:
            list[LogEntry]: Login activity for the user sorted by timestamp.
        """

        timeline = self.get_activity_timeline()

        return [
            entry for entry in timeline
            if entry.ip == ip
        ]
    
    def print_activity_timeline_by_ip(self, ip: str) -> None:
        """
        Prints all login activity for a specific IP sorted chronologically.

        Args:
            username (str): IP to filter by.

        Returns:
            None
        """

        timeline = self.get_activity_timeline_by_ip(ip)

        if not timeline:
            print(f"\nNo timeline recovered for IP '{ip}'.")
            return

        print(f"\n=== Activity Timeline for IP: {ip} ===\n")

        for entry in timeline:
            time_str = (
                entry.timestamp.strftime("%H:%M:%S")
                if entry.timestamp
                else "Unknown"
            )

            print(
                f"   [{entry.status}] "
                f"{time_str} "
                f"{entry.user} from {entry.ip}"
            )
            
    def print_all_ips(self) -> None:
        """
        Prints all unique IP addresses.
        
        Returns:
            None
        """

        timeline = self.get_activity_timeline()

        unique_ips = {
            entry.ip
            for entry in timeline
        } 

        if not unique_ips:
            print("\nNo IP addresses found.")
            return

        print("\n=== All Available IP Addresses ===\n")

        for ip in sorted(unique_ips):
            print(f"   {ip}")