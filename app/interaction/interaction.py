from app.log_analyser.log_analyser import LogAnalyser
from app.log_analyser.log_reporter import LogReporter
from app.config import MAX_ATTEMPTS, TIME_WINDOW_SECONDS

from app.interaction.menus import display_log_analysis_menu, current_config
from app.interaction.filters import integer_validation, handle_filter_menu, get_time_range
from app.interaction.configuration import configure

import os
from colorama import Fore
from datetime import datetime


class Interaction:
    """
    Provides a command-line interface for interacting with the log analyser.

    Handles:
    - User input
    - Menu display
    - Triggering analysis and report functions
    """
    def __init__(self, analyser, reporter):
        self.analyser: LogAnalyser = analyser
        self.reporter: LogReporter = reporter
        self.running = True
        self.threshold = MAX_ATTEMPTS
        self.window_seconds = TIME_WINDOW_SECONDS

    def run(self) -> None:
        """
        Runs the main interaction loop for the application.

        Displays the menu, processes user input, and executes the
        corresponding actions until the user chooses to exit.

        Returns:
            None
        """
        while self.running:
            display_log_analysis_menu()
            choice = input("\nSelect an option (1-19): ").strip()

            if choice == "1":
                current_config(self.threshold, self.window_seconds)
                print(
                    Fore.GREEN
                    + "\n=== Log Analysis Report ===\n"
                )

                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                print(
                    Fore.CYAN
                    + f"Generated: {now}\n"
                )

                if not self.analyser.failed_logins and not self.analyser.successful_logins:
                    print("Log file contained no relevant login activity.\n")

                print(
                    Fore.LIGHTRED_EX
                    + "=== Attention Needed ===\n"
                )

                total_ips = self.reporter.get_total_number_of_unique_ip_addresses()
                print(
                    Fore.CYAN
                    + f"Number of unique IPs: {total_ips}\n"
                )

                total = self.reporter.get_total_failed_login_attempts()
                print(
                    Fore.CYAN
                    + f"Total number of failed logins: {total}"
                )

                self.reporter.print_suspicious_ips()

                self.reporter.print_failed_logins()

                self.reporter.print_brute_force_results(self.threshold, self.window_seconds)

                self.reporter.print_most_targeted_user()

                self.reporter.print_suspicious_success()

                self.reporter.print_user_targeting(self.threshold)

                print(
                    Fore.CYAN
                    + "\n=== Standard Logins ===\n"
                )

                total_ = self.reporter.get_total_successful_logins()
                print(
                    Fore.LIGHTCYAN_EX
                    + f"Total number of successful logins: {total_}"
                )                

                self.reporter.print_successful_logins()
                
                print(
                    Fore.MAGENTA
                    + "\n=== End of Report ==="
                )

            elif choice == "2":
                self.reporter.print_attack_summary()

            elif choice == "3":
                self.reporter.print_attack_statistics()

            # === Investigation ===

            elif choice == "4":
                handle_filter_menu(
                    reporter=self.reporter,
                    title="Timeline",
                    show_function=self.reporter.print_activity_timeline,
                    filters=["ip", "username"]
                )

            elif choice == "5":
                handle_filter_menu(
                    reporter=self.reporter,
                    title="Suspicious Activity",
                    show_function=self.reporter.print_suspicious_activity,
                    filters=["ip", "username", "severity"]
                )

            elif choice == "6":
                handle_filter_menu(
                    reporter=self.reporter,
                    title="Failed Logins",
                    show_function=self.reporter.print_failed_logins,
                    filters=["ip", "username", "severity", "status"]
                )

            # === Detection ===
            
            elif choice == "7":
                handle_filter_menu(
                    reporter=self.reporter,
                    title="Suspicious IPs",
                    show_function=self.reporter.print_suspicious_ips,
                    filters=["ip", "severity"]
                )

            elif choice == "8":

                threshold = integer_validation(
                    f"\nEnter threshold (default = {self.threshold}): ",
                    self.threshold,
                    label="threshold"
                )

                window_seconds = integer_validation(
                    f"Enter time window (default = {self.window_seconds}): ",
                    self.window_seconds,
                    label="time window"
                )

                self.reporter.print_brute_force_results(
                    threshold,
                    window_seconds
                )

            elif choice == "9":
                self.reporter.print_most_targeted_user()

            elif choice == "10":
                self.reporter.print_suspicious_success()

            elif choice == "11":

                threshold = integer_validation(
                    f"\nEnter threshold (default = {self.threshold}): ",
                    self.threshold,
                    label="threshold"
                )

                self.reporter.print_user_targeting(threshold)

            # === General Information ===

            elif choice == "12":
                handle_filter_menu(
                    reporter=self.reporter,
                    title="Successful Logins",
                    show_function=self.reporter.print_successful_logins,
                    filters=["ip", "username", "severity", "status"]
                )

            elif choice == "13":

                total = self.reporter.get_total_failed_login_attempts()

                print(f"\nTotal failed logins: {total}")

            elif choice == "14":

                total_ips = self.reporter.get_total_number_of_unique_ip_addresses()

                print(f"\nUnique IP count: {total_ips}")

            # === Configuration ===

            elif choice == "15":

                print("\n=== Export Options ===\n")
                print("1. Failed Logins")
                print("2. Successful Logins")
                print("3. Activity Timeline")

                export_choice = input(
                    "\nSelect export option: "
                ).strip()

                data = []
                title = ""

                if export_choice == "1":

                    severity = input(
                        "\nSeverity filter (optional): "
                    ).strip().upper()

                    severity = severity if severity else None

                    data = self.reporter.get_failed_logins(
                        severity=severity
                    )

                    title = "Failed Logins"

                elif export_choice == "2":

                    data = self.reporter.get_successful_logins()

                    title = "Successful Logins"

                elif export_choice == "3":

                    start_time, end_time = get_time_range()

                    data = self.reporter.get_activity_timeline(
                        start_time=start_time,
                        end_time=end_time
                    )

                    title = "Activity Timeline"

                else:
                    print("\nInvalid export option.")
                    continue

                file_path = input(
                    "\nEnter report filename (.txt/.json): "
                ).strip()

                file_path = os.path.join(
                    "reports",
                    file_path
                )

                if file_path.endswith(".txt"):

                    self.reporter.export_txt(
                        file_path,
                        title,
                        data
                    )

                elif file_path.endswith(".json"):

                    self.reporter.export_json(
                        file_path,
                        title,
                        data
                    )

                else:

                    print("\nInvalid file extension.")

            elif choice == "16":
                file_path = input("Enter log file path: ")
                self.analyser.reset()
                file_path = "log_files/" + file_path
                self.analyser.analyse(file_path)

            elif choice == "17":
                configure(self)

            elif choice == "18":
                current_config(self.threshold, self.window_seconds)
            
            elif choice == "19":
                print("Goodbye!")
                self.running = False           

            else:
                print("\nInvalid choice. Please try again.")