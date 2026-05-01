from app.log_analyser.log_analyser import LogAnalyser
from app.log_analyser.log_reporter import LogReporter

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

    def display_menu(self) -> None:
        """
        Prints the display menu for Log Analysis

        Returns:
            None
        """
        print("\n--- Log Analysis Menu ---\n")
        print("1. Show full report")
        print("2. Show total failed logins")
        print("3. Show suspicious IPs")
        print("4. Show failed login details")
        print("5. Show successful logins")
        print("6. Show unique IP count")
        print("7. Show brute force detection")
        print("8. Show targeted users")
        print("9. Show suspicious success")
        print("10. Export report to file")
        print("11. Analyse new file")
        print("12. Exit")

    def run(self) -> None:
        """
        Runs the main interaction loop for the application.

        Displays the menu, processes user input, and executes the
        corresponding actions until the user chooses to exit.

        Returns:
            None
        """
        while self.running:
            self.display_menu()
            choice = input("\nSelect an option (1-12): ").strip()

            if choice == "1":
                print("\n--- Log Analysis Report ---\n")

                if not self.analyser.failed_logins and not self.analyser.successful_logins:
                    print("Log file contained no relevant login activity.\n")

                print("--- Attention Needed! ---\n")

                total_ips = self.reporter.get_total_number_of_unique_ip_addresses()
                print(f"Number of unique IPs: {total_ips}\n")

                total = self.reporter.get_total_failed_login_attempts()
                print(f"Total number of failed logins: {total}")

                self.reporter.print_suspicious_ips()

                print()

                self.reporter.print_failed_logins()

                print()

                self.reporter.print_brute_force_results()

                print()

                self.reporter.print_most_targeted_user()

                print()

                self.reporter.detect_suspicious_success()

                print("\n--- Standard Logins ---\n")

                total_ = self.reporter.get_total_successful_logins()
                print(f"Total number of successful logins: {total_}\n")

                self.reporter.print_successful_logins()

            elif choice == "2":
                print()
                total = self.reporter.get_total_failed_login_attempts()
                print(f"Total number of failed logins: {total}")

            elif choice == "3":
                print()
                self.reporter.print_suspicious_ips()

            elif choice == "4":
                print()
                self.reporter.print_failed_logins()

            elif choice == "5":
                print()
                self.reporter.print_successful_logins()

            elif choice == "6":
                print()
                total_ips = self.reporter.get_total_number_of_unique_ip_addresses()
                print(f"Number of unique IPs: {total_ips}\n")

            elif choice == "7":
                print()
                self.reporter.print_brute_force_results()

            elif choice == "8":
                print()
                self.reporter.print_most_targeted_user()

            elif choice == "9":
                print()
                self.reporter.detect_suspicious_success()

            elif choice == "10":
                file_path = input("Enter report file path: ")
                file_path = "reports/" + file_path
                self.reporter.export_report(file_path)

            elif choice == "11":
                file_path = input("Enter log file path: ")
                self.analyser.reset()
                file_path = "log_files/" + file_path
                self.analyser.analyse(file_path)

            elif choice == "12":
                print("Goodbye!")
                self.running = False

            else:
                print("Invalid choice. Please try again.")