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
        print("2. Show attack summary")
        print("3. Show total failed logins")
        print("4. Show suspicious IPs")
        print("5. Show failed login details")
        print("6. Show successful logins")
        print("7. Show unique IP count")
        print("8. Show brute force detection")
        print("9. Show targeted users")
        print("10. Show suspicious success")
        print("11. Show user-targeted attacks")
        print("12. Export report to file")
        print("13. Analyse new file")
        print("14. Exit")

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

                print("!!! Attention Needed !!!\n")

                total_ips = self.reporter.get_total_number_of_unique_ip_addresses()
                print(f"Number of unique IPs: {total_ips}\n")

                total = self.reporter.get_total_failed_login_attempts()
                print(f"Total number of failed logins: {total}")

                self.reporter.print_suspicious_ips()

                self.reporter.print_failed_logins()

                self.reporter.print_brute_force_results()

                self.reporter.print_most_targeted_user()

                self.reporter.detect_suspicious_success()

                self.reporter.print_user_targeting()

                print("\n--- Standard Logins ---\n")

                total_ = self.reporter.get_total_successful_logins()
                print(f"Total number of successful logins: {total_}")

                self.reporter.print_successful_logins()

            elif choice == "2":
                self.reporter.print_attack_summary()

            elif choice == "3":
                total = self.reporter.get_total_failed_login_attempts()
                print(f"\nTotal number of failed logins: {total}")

            elif choice == "4":
                self.reporter.print_suspicious_ips()

            elif choice == "5":
                self.reporter.print_failed_logins()

            elif choice == "6":
                self.reporter.print_successful_logins()

            elif choice == "7":
                total_ips = self.reporter.get_total_number_of_unique_ip_addresses()
                print(f"\nNumber of unique IPs: {total_ips}")

            elif choice == "8":
                self.reporter.print_brute_force_results()

            elif choice == "9":
                self.reporter.print_most_targeted_user()

            elif choice == "10":
                self.reporter.detect_suspicious_success()

            elif choice == "11":
                self.reporter.print_user_targeting()

            elif choice == "12":
                file_path = input("Enter report file path (.txt/.json): ")
                file_path = "reports/" + file_path
                if file_path.endswith(".txt"):                 
                    self.reporter.export_txt(file_path)
                elif file_path.endswith(".json"):                 
                    self.reporter.export_json(file_path)

            elif choice == "13":
                file_path = input("Enter log file path: ")
                self.analyser.reset()
                file_path = "log_files/" + file_path
                self.analyser.analyse(file_path)

            elif choice == "14":
                print("Goodbye!")
                self.running = False

            else:
                print("Invalid choice. Please try again.")