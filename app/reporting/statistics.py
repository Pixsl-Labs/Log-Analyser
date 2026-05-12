from app.config import MAX_ATTEMPTS


class Statistics:
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

        total_brute_force = len(self.detect_bruteforce())

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