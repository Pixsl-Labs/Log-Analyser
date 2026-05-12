from datetime import datetime

from app.log_analyser.log_entry import LogEntry


class Investigation:
    def get_failed_logins_by_user(self, username: str) -> list:
        """
        Returns all failed login attempts for a specific user.
        """

        results = []

        for entry in self.analyser.failed_logins:
            if entry.user.lower() == username.lower():
                results.append(entry)

        return results

    def get_failed_logins_by_ip(self, ip: str) -> list:
        """
        Returns all failed login attempts for a specific IP address.
        """

        results = []

        for entry in self.analyser.failed_logins:
            if entry.ip == ip:
                results.append(entry)

        return results

    def print_failed_logins_by_ip(self, ip: str) -> None:
        """
        Prints failed login attempts for a specific IP address.
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
        """

        results = self.get_failed_logins_by_user(username)

        if not results:
            print(f"\nNo failed logins found for user '{username}'.")
            return

        print(f"\n=== Failed Logins for User: {username} ===")

        print(f"\n   Total failed attempts: {len(results)}\n")

        for entry in results:
            print(f"   {entry.user} failed login from {entry.ip}")

    def get_activity_by_ip(self, ip: str) -> list:
        """
        Returns all login activity associated with a specific IP address.
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
        """

        results = self.get_activity_by_ip(ip)

        if not results:
            print(f"\nNo activity found for IP '{ip}'")
            return

        print(f"\n=== Activity For IP: {ip} ===")

        print(f"\n   Total events: {len(results)}\n")

        for entry in results:
            print(
                f"   [{entry.status}] "
                f"User '{entry.user}' "
                f"at {entry.timestamp}"
            )

    def print_suspicious_activity_by_username(
            self,
            username: str
        ) -> None:
        """
        Prints all login activity associated with a specific user.
        """

        results = self.get_activity_by_username(username)

        if not results:
            print(f"\nNo activity found for user '{username}'")
            return

        print(f"\n=== Activity For User: {username} ===")

        print(f"\n   Total events: {len(results)}\n")

        for entry in results:
            print(
                f"   [{entry.status}] "
                f"User '{entry.user}' "
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

    def get_activity_timeline(self) -> list[LogEntry]:
        """
        Returns all login activity sorted chronologically.
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

    def get_activity_timeline_by_user(
            self,
            username: str
        ) -> list[LogEntry]:
        """
        Returns user activity sorted chronologically.
        """

        timeline = self.get_activity_timeline()

        return [
            entry for entry in timeline
            if entry.user.lower() == username.lower()
        ]

    def print_activity_timeline_by_user(
            self,
            username: str
        ) -> None:
        """
        Prints activity timeline for a user.
        """

        timeline = self.get_activity_timeline_by_user(
            username
        )

        if not timeline:
            print(
                f"\nNo timeline recovered "
                f"for user '{username}'."
            )
            return

        print(
            f"\n=== Activity Timeline "
            f"for User: {username} ===\n"
        )

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

    def get_activity_timeline_by_ip(
            self,
            ip: str
        ) -> list[LogEntry]:
        """
        Returns IP activity sorted chronologically.
        """

        timeline = self.get_activity_timeline()

        return [
            entry for entry in timeline
            if entry.ip == ip
        ]

    def print_activity_timeline_by_ip(
            self,
            ip: str
        ) -> None:
        """
        Prints activity timeline for an IP.
        """

        timeline = self.get_activity_timeline_by_ip(ip)

        if not timeline:
            print(
                f"\nNo timeline recovered "
                f"for IP '{ip}'."
            )
            return

        print(
            f"\n=== Activity Timeline "
            f"for IP: {ip} ===\n"
        )

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