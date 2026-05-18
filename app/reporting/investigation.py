from datetime import time, datetime
from colorama import Fore

from app.log_analyser.log_entry import LogEntry
from app.utils.filtering import filter_log_entries
from app.utils.colours import get_status_colour, get_severity_colour


class Investigation:    
    def get_suspicious_activity(
        self,
        ip: str | None=None,
        username: str | None=None,
        severity: str | None=None,
        status: str | None=None,
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

        return filter_log_entries(
            results,
            ip=ip,
            username=username,
            severity=severity,
            status=status,
            start_time=start_time,
            end_time=end_time
        )
    
    def print_suspicious_activity(
        self,
        ip: str | None=None,
        username: str | None=None,
        severity: str | None=None,
        status: str | None=None,
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
            status=status,
            start_time=start_time,
            end_time=end_time
        )

        if not results:
            print("\nNo matching suspicious activity found.")
            return
        
        print(
            Fore.GREEN
            + "\n=== Suspicious Activity ==="
        )

        print(
            Fore.CYAN
            + f"\n   Total events: {len(results)}\n"
        )

        for entry in results:
            time_str = (
                entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if entry.timestamp
                else "Unknown"
            )

            status_colour = get_status_colour(
                entry.status
            )

            severity_colour = get_severity_colour(
                entry.severity
            )

            print(
                f"   "
                f"{status_colour}"
                f"[{entry.status:^9}] "
                f"{time_str:<20} "
                f"{entry.user:<7} "
                f"{entry.ip:<13} "
                f"{Fore.RESET}"
                f"{severity_colour}"
                f"[{entry.severity:^8}]"
            )

    def get_activity_timeline(
        self,
        ip: str | None=None,
        username: str | None=None,
        severity: str | None=None,
        status: str | None=None,
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

        results = filter_log_entries(
            results,
            ip=ip,
            username=username,
            severity=severity,
            status=status,
            start_time=start_time,
            end_time=end_time
        )

        return sorted(
            results,
            key=lambda entry: (
                entry.timestamp or datetime.min
            )
        )
    
    def print_activity_timeline(
        self,
        ip: str | None=None,
        username: str | None=None,
        severity: str | None=None,
        status: str | None=None,
        start_time: time | None=None,
        end_time: time | None=None
    ) -> None:
        """
        Prints filtered activity timeline.
        """
        results = self.get_activity_timeline(
            ip=ip,
            username=username,
            severity=severity,
            status=status,
            start_time=start_time,
            end_time=end_time
        )

        if not results:
            print("\nNo matching activity timeline found.")
            return
        
        print(
            Fore.GREEN
            + "\n=== Activity Timeline ==="
        )

        print(
            Fore.CYAN
            + f"\n   Total events: {len(results)}\n"
        )

        for entry in results:
            time_str = (
                entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if entry.timestamp
                else "Unknown"
            )

            status_colour = get_status_colour(
                entry.status
            )

            print(
                f"   "
                f"{status_colour}"
                f"[{entry.status:^9}] "
                f"{time_str:<20} "
                f"{entry.user:<7} "
                f"{entry.ip}"
            )

        print(
            Fore.MAGENTA
            + "\n=== End of Report ==="
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