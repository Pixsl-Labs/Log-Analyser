from app.log_analyser.log_analyser import LogAnalyser
from app.log_analyser.log_reporter import LogReporter

class Interaction:
    def __init__(self, analyser, reporter):
        self.analyser: LogAnalyser = analyser
        self.reporter: LogReporter = reporter
        self.running = True

    def display_menu(self):
        print("\n--- Log Analysis Menu ---")
        print("1. Show full report")
        print("2. Show total failed logins")
        print("3. Show suspicious IPs")
        print("4. Show failed login details")
        print("5. Show successful logins")
        print("6. Show unique IP count")
        print("7. Analyse new file")
        print("8. Exit")

    def run(self):
        while self.running:
            self.display_menu()
            choice = input("\nSelect an option (1-8): ").strip()

            if choice == "1":
                print("\n--- Full Report ---\n")

                self.reporter.get_total_number_of_unique_ip_addresses()
                self.reporter.get_total_failed_login_attempts()

                print()

                self.reporter.get_suspicious_ips()

                print()

                self.reporter.get_failed_logins()

                print()

                self.reporter.get_total_successful_login_attempts()
                self.reporter.get_successful_logins()

            elif choice == "2":
                print()
                self.reporter.get_total_failed_login_attempts()

            elif choice == "3":
                print()
                self.reporter.get_suspicious_ips()

            elif choice == "4":
                print()
                self.reporter.get_failed_logins()

            elif choice == "5":
                print()
                self.reporter.get_successful_logins()

            elif choice == "6":
                print()
                self.reporter.get_total_number_of_unique_ip_addresses()

            elif choice == "7":
                file_path = input("Enter log file path: ")
                self.analyser.reset()
                self.analyser.analyse(file_path)

            elif choice == "8":
                print("Goodbye!")
                self.running = False

            else:
                print("Invalid choice. Please try again.")