from app.log_analyser.log_entry import LogEntry
from app.utils.filtering import filter_log_entries

from datetime import time, datetime


class Statistics:
    def get_failed_logins(
        self,
        ip: str | None=None,
        username: str | None=None,
        severity: str | None=None,
        status: str | None=None,
        start_time: time | None=None,
        end_time: time | None=None
    ) -> list[LogEntry]:
        """
        Returns filtered failed login attempts.
        """

        return filter_log_entries(
            self.analyser.failed_logins,
            ip=ip,
            username=username,
            severity=severity,
            status=status,
            start_time=start_time,
            end_time=end_time
        )
    
    def print_failed_logins(
        self,
        ip: str | None=None,
        username: str | None=None,
        severity: str | None=None,
        status: str | None=None,
        start_time: time | None=None,
        end_time: time | None=None
    ) -> None:
        """
        Prints filtered failed logins.
        """

        results = self.get_failed_logins(
            ip=ip,
            username=username,
            severity=severity,
            status=status,
            start_time=start_time,
            end_time=end_time
        )

        if not results:
            print("\nNo matching failed logins found.")
            return
        
        results = sorted(
            results,
            key=lambda entry: entry.timestamp or datetime.min
        )
        
        print("\n=== Failed Login Results ===")
        print(f"\n   Total results: {len(results)}\n")

        for entry in results:
            print(
                f"   [{entry.severity:<6}] "
                f"{entry.user:<12} "
                f"{entry.ip}"
            )

    def get_successful_logins(
        self,
        ip: str | None=None,
        username: str | None=None,
        severity: str | None=None,
        status: str | None=None,
        start_time: time | None=None,
        end_time: time | None=None
        ) -> list[LogEntry]:
        """
        Returns filtered successful logins.
        """

        return filter_log_entries(
            self.analyser.sucessful_logins,
            ip=ip,
            username=username,
            severity=severity,
            status=status,
            start_time=start_time,
            end_time=end_time
        )

    def print_successful_logins(
        self,
        ip: str | None=None,
        username: str | None=None,
        severity: str | None=None,
        status: str | None=None,
        start_time: time | None=None,
        end_time: time | None=None
    ) -> None:
        """
        Prints filtered successful logins.
        """

        results = self.get_successful_logins(
            ip=ip,
            username=username,
            severity=severity,
            status=status,
            start_time=start_time,
            end_time=end_time
        )

        if not results:
            print("\nNo successful logins found.")
            return
        
        results = sorted(
            results,
            key=lambda entry: entry.timestamp or datetime.min
        )

        print("\n=== Successful Logins ===")
        print(f"\n   Total results: {len(results)}\n")

        for entry in results:

            time_str = (
                entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if entry.timestamp
                else "Unknown"
            )

            print(
                f"   [{entry.status:<7}] "
                f"{time_str:<20} "
                f"{entry.user:<12} "
                f"{entry.ip}"
            )

    def get_total_failed_login_attempts(self) -> int:
        """
        Returns the total number of failed logins detected

        Returns:
            int: Total number of failed login attempts
        """
        return sum(self.analyser.failed_ip_counts.values())

    def get_total_successful_logins(self) -> int:
        """
        Returns the total number of successful logins

        Returns:
            int: Total number of successful logins
        """
        return len(self.analyser.successful_logins)

    def get_total_suspicious_ips(self) -> int:
        """
        Returns the total number of suspicious IPs detected.

        Returns:
            int: Total number of suspicious IPs
        """
        return len(self.analyser.failed_ip_counts)

    def get_total_number_of_unique_ip_addresses(self) -> int:
        """
        Returns the total number of unique IP addresses detected

        Returns:
            int: Total number of unique IP addresses identified
        """
        all_ips = set()

        for entry in self.analyser.failed_logins:
            all_ips.add(entry.ip)

        for entry in self.analyser.successful_logins:
            all_ips.add(entry.ip)

        return len(all_ips)

    def get_attack_statistics(self) -> dict:
        """
        Returns a high-level summary of attack statistics.

        Returns:
            dict: Summary statistics for analysed log data
        """

        total_failed = self.get_total_failed_login_attempts()

        total_successful = self.get_total_successful_logins()

        total_suspicious_ips = self.get_total_suspicious_ips()

        total_brute_force = len(self.get_bruteforce())

        total_targeted_users = len(self.get_most_targeted_users())

        highest_severity = "NONE"

        if self.analyser.failed_ip_counts:
            highest_attempts = max(self.analyser.failed_ip_counts.values())
            highest_severity = self.get_severity_level(highest_attempts)

        top_attacker = None

        if self.analyser.failed_ip_counts:
            top_ip, attempts = max(
                self.analyser.failed_ip_counts.items(),
                key=lambda x: x[1]
            )

            top_attacker = f"{top_ip} ({attempts} attempts)"

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
    
    def get_most_targeted_users(self) -> list[tuple[str, int]]:
        """
        Returns users sorted by failed login attempts.
        """

        user_counts = {}

        for entry in self.analyser.failed_logins:
            user_counts[entry.user] = (
                user_counts.get(entry.user, 0) + 1
            )

        return sorted(
            user_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

    def print_most_targeted_user(self) -> None:
        """
        Prints the most targeted users.
        """

        sorted_users = self.get_most_targeted_users()

        if not sorted_users:
            print("\nNo targeted users found.")
            return

        print("\n=== Most Targeted Users ===\n")

        for user, count in sorted_users:
            print(f"   {user} -> {count} attempts")

    def print_attack_statistics(self) -> None:
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

    def print_analysis_summary(self) -> None:
        """
        Prints a condensed analysis summary.
        """

        stats = self.get_attack_statistics()

        print("\n=== Analysis Summary ===")

        print(f"\nFailed attempts: {stats['failed_attempts']}")
        print(f"Successful logins: {stats['successful_logins']}")
        print(f"Suspicious IPs: {stats['suspicious_ips']}")
        print(f"Brute-force alerts: {stats['brute_force_alerts']}")