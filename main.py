import re
import sys

MAX_ATTEMPTS = 5

if len(sys.argv) > 1:
    log_file = sys.argv[1]
else:
    log_file = input("Please enter the file name that you would like to analyse: ")

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


class LogAnalyser:
    def __init__(self):
        self.failed_logins = []
        self.successful_logins = []
        self.failed_ip_counts = {}

    def analyse(self, file_path):
        found_failed = False
        found_success = False

        try:
            with open(file_path, 'r') as file:
                for line in file:
                    if "failed password" in line.lower():
                        found_failed = True
                        self.extract_failed_ip(line)
                    elif "accepted password" in line.lower() or "session opened" in line.lower():
                        found_success = True
                        self.extract_successful_login(line)

            print(f"\nAnalysing file: {file_path}")

            if not found_failed:
                print("No failed login attempts found.")
            if not found_success:
                print("No successful logins found.")

            return True

        except FileNotFoundError:
            print(f"\nError: The file '{file_path}' was not found.")
            return False

    def extract_failed_ip(self, line):
        ip_match = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', line)
        user_match = re.search(r'Failed password for (?:invalid user )?(\w+)', line)

        ip = ip_match.group() if ip_match else "unknown"
        user = user_match.group(1) if user_match else "unknown"

        self.failed_logins.append((ip, user))

        if ip_match:
            self.failed_ip_counts[ip] = self.failed_ip_counts.get(ip, 0) + 1

    def extract_successful_login(self, line):
        line_lower = line.lower()
        ip_match = re.search(r'\b(?:from|for .*? from) ([\d\.]+)', line_lower)
        user_match = re.search(r'for (\w+)', line_lower)

        ip = ip_match.group(1) if ip_match else "unknown"
        user = user_match.group(1) if user_match else "unknown"

        self.successful_logins.append((ip, user))

    def reset(self):
        self.failed_logins = []
        self.successful_logins = []
        self.failed_ip_counts = {}


class LogReporter:
    def __init__(self, analyser):
        self.analyser: LogAnalyser = analyser

    def get_total_failed_login_attempts(self):
        total = sum(self.analyser.failed_ip_counts.values())
        print(f"Total number of failed logins: {total}")

    def get_suspicious_ips(self):
        if not self.analyser.failed_ip_counts:
            return

        sorted_ips = sorted(self.analyser.failed_ip_counts.items(), key=lambda x: x[1], reverse=True)

        print("Suspicious IPs (failed attempts):")
        for ip, count in sorted_ips:
            status = "Investigate" if count >= MAX_ATTEMPTS else "Low risk"
            print(f"   {ip} -> {count} attempts ({status})")

    def get_failed_logins(self):
        if not self.analyser.failed_logins:
            return

        print("Failed logins:")
        for ip, user in self.analyser.failed_logins:
            print(f"   User '{user}' failed login from {ip}")

    def get_successful_logins(self):
        if not self.analyser.successful_logins:
            return

        print("Successful logins:")
        for ip, user in self.analyser.successful_logins:
            print(f"   User '{user}' logged in from {ip}")

    def get_total_successful_login_attempts(self):
        total = len(self.analyser.successful_logins)
        print(f"Total number of successful logins: {total}")

    def get_total_number_of_unique_ip_addresses(self):
        all_ips = set(ip for ip, _ in self.analyser.failed_logins + self.analyser.successful_logins)
        print(f"Number of unique IPs: {len(all_ips)}")


if __name__ == "__main__":
    analyser = LogAnalyser()
    success = analyser.analyse(log_file)

    if success:
        reporter = LogReporter(analyser)
        interaction = Interaction(analyser, reporter)
        interaction.run()
    else:
        print("\nAnalysis stopped due to missing file.")