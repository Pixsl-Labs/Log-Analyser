from datetime import time, datetime

from app.log_analyser.log_entry import LogEntry

class Investigation:    
    def get_suspicious_activity(
        self,
        ip: str | None=None,
        username: str | None=None,
        severity: str | None=None,
        start_time: time | None=None,
        end_time: time | None=None
    ) -> list[LogEntry]:
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

        if start_time:
            results = [
                entry for entry in results
                if entry.timestamp
                and entry.timestamp.time() >= start_time
            ]

        if end_time:
            results = [
                entry for entry in results
                if entry.timestamp
                and entry.timestamp.time() <= end_time
            ]

        return results
    
    def print_suspicious_activity(
        self,
        ip: str | None=None,
        username: str | None=None,
        severity: str | None=None,
        start_time: time | None=None,
        end_time: time | None=None
    ) -> None:
        """
        Prints filtered suspicious activity.
        """

        results = self.get_suspicious_activity(
            ip=ip,
            username=username,
            severity=severity,
            start_time=start_time,
            end_time=end_time
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

    def get_activity_timeline(
        self,
        ip: str | None=None,
        username: str | None=None,
        start_time: time | None=None,
        end_time: time | None=None
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

        if start_time:
            results = [
                entry for entry in results
                if entry.timestamp
                and entry.timestamp.time() >= start_time
            ]

        if end_time:
            results = [
                entry for entry in results
                if entry.timestamp
                and entry.timestamp.time() <= end_time
            ]

        return sorted(
            results,
            key=lambda entry: entry.timestamp or datetime.min
        )
    
    def print_activity_timeline(
        self,
        ip: str | None=None,
        username: str | None=None,
        start_time: time | None=None,
        end_time: time | None=None
    ) -> None:
        """
        Prints filtered activity timeline.
        """
        results = self.get_activity_timeline(
            ip=ip,
            username=username,
            start_time=start_time,
            end_time=end_time
        )

        if not results:
            print("\nNo matching activity timeline found.")
            return
        
        print("\n=== Activity Timeline ===\n")
        print(f"\n   Total events: {len(results)}\n")

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