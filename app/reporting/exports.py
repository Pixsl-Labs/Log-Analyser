import json
from datetime import datetime


class Export:
    def export_txt(self, filename: str) -> None:
        """
        Exports analysis results to TXT format.
        """

        now = datetime.now()

        with open(filename, "w") as f:
            f.write("=== Log Analysis Report ===\n\n")

            f.write(
                now.strftime(
                    "Generated: %Y-%m-%d %H:%M:%S\n\n"
                )
            )

            stats = self.get_attack_statistics()

            for key, value in stats.items():
                f.write(f"{key}: {value}\n")

        print(f"TXT report exported to {filename}")

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
                for ip, count
                in self.analyser.failed_ip_counts.items()
            ]
        }

        with open(filename, "w") as f:
            json.dump(data, f, indent=4)

        print(f"JSON report exported to {filename}")