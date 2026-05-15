import json

from datetime import datetime

from dataclasses import asdict, is_dataclass


class Export:

    def export_txt(
        self,
        filename: str,
        title: str,
        data: list
    ) -> None:
        """
        Exports filtered results to TXT format.
        """

        now = datetime.now()

        with open(filename, "w") as f:

            f.write(f"=== {title} ===\n\n")

            f.write(
                now.strftime(
                    "Generated: %Y-%m-%d %H:%M:%S\n\n"
                )
            )

            if not data:
                f.write("No results found.\n")

            else:
                for item in data:
                    if hasattr(item, "ip"):

                        timestamp = (
                            item.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                            if item.timestamp
                            else "Unknown"
                        )

                        f.write(
                            f"[{item.status:<7}] "
                            f"{timestamp} "
                            f"{item.user:<12} "
                            f"{item.ip:<15} "
                            f"[{item.severity}]\n"
                        )

                    else:
                        f.write(f"{item}\n")

        print(f"\nTXT report exported to {filename}")

    def export_json(
        self,
        filename: str,
        title: str,
        data: list
    ) -> None:
        """
        Exports filtered results to JSON format.
        """

        now = datetime.now()

        export_data = {
            "generated_at": now.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "title": title,
            "results": [
                {
                    key: (
                        value.strftime("%Y-%m-%d %H:%M:%S")
                        if isinstance(value, datetime)
                        else value
                    )
                    for key, value in asdict(item).items()
                }
                if is_dataclass(item)
                else item
                for item in data
            ]
        }

        with open(filename, "w") as f:
            json.dump(export_data, f, indent=4)

        print(f"\nJSON report exported to {filename}")