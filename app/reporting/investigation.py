from datetime import datetime

from app.log_analyser.log_entry import LogEntry
from app.log_analyser.log_analyser import LogAnalyser


class Investigation:
    def __init__(self, analyser: LogAnalyser):
        self.analyser = analyser
    
    def get_suspicious_activity(
            self,
            ip=None,
            username=None,
            severity=None
    ) -> list:
        """
        Returns filtered suspicious activity.
        """

        results = (
            self.analyser.failed_logins
            + self.analyser.successful_logins
        )

        if ip:
            results = [
                entry for entry in results
                if entry.ip == ip
            ]

        if username:
            results = [
                entry for entry in results
                if entry.user.lower() == username.lower()
            ]
        
        if severity:
            results = [
                entry for entry in results
                if entry.severity == severity
            ]

        return results
    
    def print_suspicious_activity(
            self,
            ip=None,
            username=None,
            severity=None
    ) -> None:
        """
        Prints filtered suspicious activity.
        """

        results = self.get_suspicious_activity(
            ip=ip,
            username=username,
            severity=severity
        )

        if not results:
            print("\nNo matching suspicious activity found.")
            return
        
        print(f"\n=== Suspicious Activity ===\n")

        print(f"\n   Total events: {len(results)}\n")

        for entry in results:
            print(
                f"   [{entry.status}] "
                f"{entry.user} "
                f"from {entry.ip} "
                f"at {entry.timestamp}"
            )

    def print_failed_logins(self) -> None:
        """
        Prints failed login attempts.
        """

        if not self.analyser.failed_logins:
            print("\nNo failed logins found.")
            return

        print("\n=== Failed Logins ===\n")

        for entry in self.analyser.failed_logins:
            print(
                f"   User '{entry.user}' "
                f"failed login from {entry.ip}"
            )

    def print_successful_logins(self) -> None:
        """
        Prints successful logins.
        """

        if not self.analyser.successful_logins:
            print("\nNo successful logins found.")
            return

        print("\n=== Successful Logins ===\n")

        for entry in self.analyser.successful_logins:
            print(
                f"   User '{entry.user}' "
                f"logged in from {entry.ip}"
            )

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

    def get_activity_timeline(
            self,
            ip=None,
            username=None
        ) -> list[LogEntry]:
        """
        Returns filtered activity timeline.
        """

        results = (
            self.analyser.failed_logins
            + self.analyser.successful_logins
        )

        if ip:
            results = [
                entry for entry in results
                if entry.ip == ip
            ]

        if username:
            results = [
                entry for entry in results
                if entry.user.lower() == username.lower()
            ]

        return sorted(
            results,
            key=lambda entry: entry.timestamp or datetime.min
        )
    
    def print_activity_timeline(
            self,
            ip=None,
            username=None
    ) -> None:
        """
        Prints filtered activity timeline.
        """
        results = self.get_activity_timeline(
            ip=ip,
            username=username
        )

        if not results:
            print("\nNo matching activity timeline found.")
            return
        
        print("\n=== Activity Timeline ===\n")

        for entry in results:
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

    def print_all_ips(self) -> None:
        """
        Prints all unique IP addresses.
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