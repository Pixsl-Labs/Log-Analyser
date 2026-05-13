from app.config import MAX_ATTEMPTS


class Summary:
    def print_attack_summary(self) -> None:
        """
        Prints a high-level summary of detected threats.
        """

        print("\n=== Attack Summary ===\n")

        total_failed = (
            self.get_total_failed_login_attempts()
        )

        print(f"Total failed attempts: {total_failed}")

        if self.analyser.failed_logins:
            top_ip = max(
                self.analyser.failed_ip_counts.items(),
                key=lambda x: x[1]
            )

            print(
                f"Top attacking IP: "
                f"{top_ip[0]} ({top_ip[1]} attempts)"
            )

        else:
            print("Top attacking IP: None")

        targeted = self.get_user_targeting()

        if targeted:
            top_user, attempts = targeted[0]

            print(
                f"Most targeted user: "
                f"{top_user} ({attempts} attempts)"
            )

        else:
            print("Most targeted user: None")

        brute = self.get_bruteforce()

        print(f"Brute-force alerts: {len(brute)}")

        targeting = self.get_user_targeting(
            MAX_ATTEMPTS
        )

        print(
            f"User-targeting alerts: "
            f"{len(targeting)}"
        )