from collections import defaultdict

from app.config import (
    MAX_ATTEMPTS,
    TIME_WINDOW_SECONDS,
    SEVERITY_LEVEL
)
from app.log_analyser.log_analyser import LogAnalyser


class Detection:
    def __init__(self, analyser: LogAnalyser):
        self.analyser = analyser

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

    def detect_bruteforce(
            self,
            threshold=MAX_ATTEMPTS,
            window_seconds=TIME_WINDOW_SECONDS
        ) -> list[tuple[str, int, float]]:
        """
        Detects brute force attacks based on failed login attempts
        within a specified time window
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
        Prints detected brute force attacks.
        """

        results = self.detect_bruteforce(
            threshold,
            window_seconds
        )

        if not results:
            print("\nNo brute force activity detected")
            return

        print("\n=== Brute Force Detected ===\n")

        for ip, attempts, diff in results:
            severity = self.get_severity_level(attempts)

            print(
                f"   {ip} -> "
                f"{attempts} attempts in {diff}s "
                f"(threshold={threshold}) "
                f"[{severity}]"
            )

    def print_suspicious_success(self) -> None:
        """
        Detects successful logins following failed attempts.
        """

        failed_ips = set(
            entry.ip
            for entry in self.analyser.failed_logins
        )

        found = False

        for entry in self.analyser.successful_logins:
            if entry.ip in failed_ips:
                if not found:
                    print("\n=== IPs with Success After Failure ===\n")
                    found = True

                print(
                    f"   {entry.ip} successfully "
                    f"logged in after failures"
                )

        if not found:
            print("\nNo suspicious success detected.")

    def detect_user_targeting(
            self,
            threshold=MAX_ATTEMPTS
        ):
        """
        Detects users being targeted by multiple IPs.
        """

        user_attempts = defaultdict(list)

        for entry in self.analyser.failed_logins:
            user_attempts[entry.user].append(entry.ip)

        results = []

        for user, ips in user_attempts.items():
            unique_ips = set(ips)

            if len(unique_ips) >= threshold:
                results.append(
                    (user, len(unique_ips), len(ips))
                )

        return results

    def print_user_targeting(
            self,
            threshold=MAX_ATTEMPTS
        ) -> None:
        """
        Prints distributed user-targeting attacks.
        """

        results = self.detect_user_targeting(threshold)

        if not results:
            print("\nNo user-targeted attacks detected.")
            return

        print("\n=== User Targeted Attacks Detected ===\n")

        for user, unique_ips, total_attempts in results:
            severity = self.get_severity_level(unique_ips)

            print(
                f"   {user} targeted by "
                f"{unique_ips} IPs "
                f"({total_attempts}) attempts "
                f"[{severity}]"
            )

    def get_suspicious_ips(
            self,
            ip=None,
            severity=None
    ) -> list:
        """
        Returns filtered suspicious IP addresses.
        """

        results = []

        sorted_ips = sorted(
            self.analyser.failed_ip_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        for current_ip, count in sorted_ips:

            current_severity = self.get_severity_level(count)

            if ip and current_ip != ip:
                continue

            if severity and current_severity != severity:
                continue

            results.append(
                (
                    current_ip,
                    count,
                    current_severity
                )
            )

        return results
    
    def print_suspicious_ips(
            self,
            ip=None,
            severity=None
    ) -> None:
        """
        Prints filtered suspicious IP addresses.
        """

        results = self.get_suspicious_ips(
            ip=ip,
            severity=severity
        )

        if not results:
            print("\nNo suspicious IPs found.")
            return
        
        print("\n=== Suspicious IPs (Failed Attempts) ===\n")

        for current_ip, count, current_severity in results:

            status = self.get_risk_level(count)

            print(
                f"   {current_ip} ->"
                f"{count} attempts "
                f"({status}) "
                f"[{current_severity}]"
            )