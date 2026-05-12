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
        
    def handle_filter_menu(
            self,
            title,
            show_all_function,
            ip_function,
            user_function
        ) -> None:
        """
        Handles reusable filtering menu for investigation features.
        
        Args:
            title (str): Menu title.
            show_all_function (callable): Function for showing all results.
            ip_function (callable): Function for IP filtering.
            user_function (callable): Function for username filtering.

        Returns:
            None
        """
        while True:
            print(f"\nFilter {title} by:")
            print("1. None")
            print("2. IP")
            print("3. User")
            print("4. Back")

            filter_choice = input("\nSelect filter (1-4): ").strip()

            if filter_choice == "1":
                show_all_function()
                break

            elif filter_choice == "2":
                self.reporter.print_all_ips()

                ip = input("\nEnter IP address: ").strip()

                if not ip:
                    print("\nNo IP entered.")
                    continue

                ip_function(ip)
                break

            elif filter_choice == "3":
                self.reporter.print_all_usernames()

                username = input("\nEnter username: ").strip()

                if not username:
                    print("\nNo username entered.")
                    continue

                user_function(username)
                break

            elif filter_choice == "4":
                break

            else:
                print(f"\n'{filter_choice}' is an invalid choice. Please try again.")

    def display_log_analysis_menu(self) -> None:
        """
        Prints the display menu for Log Analysis

        Returns:
            None
        """

        print("\n=== Log Analysis Menu ===\n")

        print("1. Show full report")
        print("2. Show attack summary")
        print("3. Show attack statistics")

        print("\n=== Investigation ===\n")

        print("4. Show activity timeline")
        print("5. Show suspicious activity")
        print("6. Show failed login details")

        print("\n=== Detection ===\n")

        print("7. Show suspicious IPs")
        print("8. Show brute force detection")
        print("9. Show targeted users")
        print("10. Show suspicious success")
        print("11. Show user-targeted attacks")

        print("\n=== General Information ===\n")

        print("12. Show successful logins")
        print("13. Show total failed logins")
        print("14. Show unique IP count")

        print("\n=== Configuration ===\n")

        print("15. Export report to file")
        print("16. Analyse new file")
        print("17. Configure settings")
        print("18. Show current configuration")
        print("19. Exit")

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
            choice = input("\nSelect an option (1-19): ").strip()

            if choice == "1":
                self.current_config()
                print("\n=== Log Analysis Report ===\n")

                if not self.analyser.failed_logins and not self.analyser.successful_logins:
                    print("Log file contained no relevant login activity.\n")

                print("=== Attention Needed ===\n")

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
                self.reporter.print_attack_statistics()

            # === Investigation ===

            elif choice == "4":
                self.handle_filter_menu(
                        "Timeline",
                        self.reporter.print_activity_timeline,
                        self.reporter.print_activity_timeline_by_ip,
                        self.reporter.print_activity_timeline_by_user
                    )

            elif choice == "5":
                total = self.reporter.get_total_failed_login_attempts()
                print(f"\nTotal number of failed logins: {total}")

            elif choice == "6":
                self.handle_filter_menu(
                        "Failed Logins",
                        self.reporter.print_suspicious_ips,
                        self.reporter.print_suspicious_activity_by_ip,
                        self.reporter.print_suspicious_activity_by_username
                    )

            # === Detection ===
            
            elif choice == "7":
                self.handle_filter_menu(
                        "Suspicious Activity",
                        self.reporter.print_suspicious_ips,
                        self.reporter.print_suspicious_activity_by_ip,
                        self.reporter.print_suspicious_activity_by_username
                    )
            
            elif choice == "8":
                self.reporter.print_brute_force_results()
            
            elif choice == "9":
                self.reporter.print_successful_logins()

            elif choice == "10":
                total_ips = self.reporter.get_total_number_of_unique_ip_addresses()
                print(f"\nNumber of unique IPs: {total_ips}")

            elif choice == "11":
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

            # === General Information ===

            elif choice == "12":
                self.reporter.print_most_targeted_user()

            elif choice == "13":
                self.reporter.detect_suspicious_success()

            elif choice == "14":
                threshold = self.integer_validation(
                    f"\nEnter threshold (default = {self.threshold}): ",
                    self.threshold,
                    label="threshold"
                )
                
                self.reporter.print_user_targeting(threshold)

            # === Configuration ===

            elif choice == "15":
                file_path = input("Enter report file path (.txt/.json): ")
                file_path = os.path.join("reports", file_path)
                if file_path.endswith(".txt"):                 
                    self.reporter.export_txt(file_path)
                elif file_path.endswith(".json"):                 
                    self.reporter.export_json(file_path)

            elif choice == "16":
                file_path = input("Enter log file path: ")
                self.analyser.reset()
                file_path = "log_files/" + file_path
                self.analyser.analyse(file_path)

            elif choice == "17":
                self.configure()

            elif choice == "18":
                self.current_config()
            
            elif choice == "19":
                print("Goodbye!")
                self.running = False           

            else:
                print("\nInvalid choice. Please try again.")