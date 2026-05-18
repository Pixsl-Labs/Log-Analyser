from collections import defaultdict
from colorama import Fore

from app.config import (
    MAX_ATTEMPTS,
    TIME_WINDOW_SECONDS,
    SEVERITY_LEVEL
)
from app.utils.colours import get_severity_colour, get_status_colour


class Detection:
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

    def get_bruteforce(
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

        results = self.get_bruteforce(
            threshold,
            window_seconds
        )

        if not results:
            print(
                Fore.LIGHTRED_EX
                + "\nNo brute force activity detected."
            )

            return

        print(
            Fore.YELLOW
            + "\n=== Brute Force Detected ===\n"
        )

        print(
            Fore.CYAN
            + f"   Total number of brute force attempts detected: {len(results)}\n"
        )

        for ip, attempts, diff in results:
            severity = self.get_severity_level(attempts)

            print(
                f"{Fore.LIGHTRED_EX}"
                f"   {ip:<12} -> "
                f"{attempts:<2} attempts "
                f"in {diff:>3.1f}s "
                f"[{severity}]"
            )

    def print_suspicious_success(self) -> None:
        """
        Detects successful logins following failed attempts.
        """

        failed_ips = {
            entry.ip
            for entry in self.analyser.failed_logins
        }

        matching_ips = {
            entry.ip
            for entry in self.analyser.successful_logins
            if entry.ip in failed_ips
        }

        if not matching_ips:
            print(
                Fore.LIGHTRED_EX
                + "\nNo suspicious success detected."
            )

            return

        print(
            Fore.YELLOW
            + "\n=== IPs with Success After Failure ==="
        )

        print(
            Fore.CYAN
            + f"\n   Total matching IPs: "
            f"{len(matching_ips)}\n"
        )

        for ip in sorted(matching_ips):

            print(
                f"{Fore.YELLOW}"
                f"   {ip:<12} -> "
                f"Successful login after failures"
            )

    def get_user_targeting(
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

        results = self.get_user_targeting(threshold)

        if not results:
            print(
                Fore.LIGHTRED_EX
                + "\nNo user-targeted attacks detected."
            )

            return

        print("\n=== User Targeted Attacks Detected ===\n")

        print(
            Fore.CYAN
            + f"   Total number of targeted users: {len(results)}\n"
        )

        for user, unique_ips, total_attempts in results:
            severity = self.get_severity_level(unique_ips)

            print(
                f"   {user} targeted by "
                f"{unique_ips} IPs "
                f"({total_attempts} attempts) "
                f"[{severity}]"
            )

    def get_suspicious_ips(
        self,
        ip: str | None=None,
        severity: str | None=None,
    ) -> list[tuple[str, int, str]]:
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
        ip: str | None=None,
        severity: str | None=None
    ) -> None:
        """
        Prints filtered suspicious IP addresses.
        """

        results = self.get_suspicious_ips(
            ip=ip,
            severity=severity
        )

        if not results:
            print(
                Fore.LIGHTRED_EX
                + "\nNo suspicious IPs found."
            )
            return
        
        print(
            Fore.YELLOW
            + "\n=== Suspicious IPs (Failed Attempts) ===\n"
        )

        print(
            Fore.CYAN
            + f"   Total number of suspicious IPs: {len(results)}\n"
        )

        for current_ip, count, current_severity in results:

            status = self.get_risk_level(count)

            severity_colour = (
                get_severity_colour(
                    current_severity
                )
            )

            print(
                f"   {current_ip:<12} -> "
                f"{count:<2} attempts "
                f"({status:^11}) "
                f"{severity_colour}"
                f"[{current_severity:^8}]"
            )