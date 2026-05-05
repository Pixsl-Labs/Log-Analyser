from app.log_analyser.log_analyser import LogAnalyser
from app.log_analyser.log_reporter import LogReporter
from app.config import MAX_ATTEMPTS, TIME_WINDOW_SECONDS

import logging, os

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

    def integer_validation(self, prompt, default, label="value"):
        """
        Prompts the user for an integer input.

        If the input is empty or invalid, returns the provided default value.

        Args:
            prompt (str): Input prompt to display to the user.
            default (int): Default value to use if input is invalid.
            label (str): Name of the value (for user messaging).

        Returns:
            int: Valid integer input or default value.
        """
        value = input(prompt).strip()

        if value == "":
            print(f"Using default {label} ({default})\n")
            return default
        
        try:
            return int(value)
        except ValueError:
            logging.error(f"Error: Invalid input, using default.")
            print(f"Using default {label} ({default})\n")
            return default

    def display_log_analysis_menu(self) -> None:
        """
        Prints the display menu for Log Analysis

        Returns:
            None
        """
        print("\n=== Log Analysis Menu ===\n")
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
        print("14. Configure settings")
        print("15. Show current configuration")
        print("16. Exit")

    def display_configuration_menu(self) -> None:
        """
        Prints the configuration menu for alerations to Log Analysis
        
        Returns:
            None
        """
        print("\n=== Configuration Menu ===\n")
        print(f"1. Maximum number of attempts (current = {self.threshold})")
        print(f"2. Maximum time window (current = {self.window_seconds})")
        print("3. Convert back to original")
        print("4. Exit")

    def current_config(self):
        """
        Prints the current configurations
        
        Returns:
            None
        """
        print("\n=== Current Configuration ===\n")
        print(f"- Threshold: {self.threshold}")
        print(f"- Time window: {self.window_seconds}")

    def configure(self):
        """
        Allows the user to configurate the current configuration settings.
        """
        while True:
            self.display_configuration_menu()
            print(f"\nCurrent config: threshold={self.threshold}, window={self.window_seconds}")
            choice = input("\nSelect option (1-4): ").strip()

            if choice == "1":
                new_value = self.integer_validation(
                    f"\nEnter max attempts (current = {self.threshold}): ",
                    self.threshold,
                    label="threshold"
                )
                
                if new_value != self.threshold:
                    self.threshold = new_value
                    print("\nSettings Updated.")
            
            elif choice == "2":
                new_value = self.integer_validation(
                    f"\nEnter time window (current = {self.window_seconds}): ",
                    self.window_seconds,
                    label="time window"
                )
                
                if new_value != self.window_seconds:
                    self.window_seconds = new_value
                    print("\nSettings Updated.")
            
            elif choice == "3":
                self.threshold = MAX_ATTEMPTS
                self.window_seconds = TIME_WINDOW_SECONDS

                print(f"\nConfigured settings have now been set back to default (threshold={self.threshold}, time window={self.window_seconds})")
            
            elif choice == "4":
                break

            else:
                print("\nInvalid choice. Please try again.")

    def run(self) -> None:
        """
        Runs the main interaction loop for the application.

        Displays the menu, processes user input, and executes the
        corresponding actions until the user chooses to exit.

        Returns:
            None
        """
        while self.running:
            self.display_log_analysis_menu()
            choice = input("\nSelect an option (1-16): ").strip()

            if choice == "1":
                print("\n=== Log Analysis Report ===\n")

                if not self.analyser.failed_logins and not self.analyser.successful_logins:
                    print("Log file contained no relevant login activity.\n")

                print("!!! Attention Needed !!!\n")

                total_ips = self.reporter.get_total_number_of_unique_ip_addresses()
                print(f"Number of unique IPs: {total_ips}\n")

                total = self.reporter.get_total_failed_login_attempts()
                print(f"Total number of failed logins: {total}")

                self.reporter.print_suspicious_ips()

                self.reporter.print_failed_logins()

                self.reporter.print_brute_force_results(self.threshold, self.window_seconds)

                self.reporter.print_most_targeted_user()

                self.reporter.detect_suspicious_success()

                self.reporter.print_user_targeting(self.threshold)

                print("\n=== Standard Logins ===\n")

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
                threshold = self.integer_validation(
                    f"\nEnter threshold (default = {self.threshold}): ",
                    self.threshold,
                    label="threshold"
                )

                window_seconds = self.integer_validation(
                    f"Enter time window (default = {self.window_seconds}): ",
                    self.window_seconds,
                    label="time window"
                )

                self.reporter.print_brute_force_results(threshold, window_seconds)

            elif choice == "9":
                self.reporter.print_most_targeted_user()

            elif choice == "10":
                self.reporter.detect_suspicious_success()

            elif choice == "11":
                threshold = self.integer_validation(
                    f"\nEnter threshold (default = {self.threshold}): ",
                    self.threshold,
                    label="threshold"
                )
                
                self.reporter.print_user_targeting(threshold)

            elif choice == "12":
                file_path = input("Enter report file path (.txt/.json): ")
                file_path = os.path.join("reports", file_path)
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
                self.configure()

            elif choice == "15":
                self.current_config()
            
            elif choice == "16":
                print("Goodbye!")
                self.running = False          

            else:
                print("\nInvalid choice. Please try again.")