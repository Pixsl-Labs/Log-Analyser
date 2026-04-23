# source venv/bin/activate
import re, sys

if len(sys.argv) < 2:
    print("Usage python main.py <file_path_of_log_file>")
    sys.exit(1)

if sys.argv[1] == "":
    log_file = input("Please enter the file name that you would like to analyse: ")
else:
    log_file = sys.argv[1]
    
print()

class AnalysisOfLogFile:
    def __init__(self):
        self.failed_count = 0
        self.success_count = 0
        self.failed_ip_counts = {}
        self.successful_logins = []
        self.max_attempts = 5
        
    def analyse(self, file_path):
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    if "failed password" in line.lower():
                        self.extract_failed_ip(line)
                    elif "accepted password" in line.lower() or "session opened" in line.lower():
                        self.extract_successful_login(line)
            return True
        except FileNotFoundError:
            print(f"Error: The file '{log_file}' was not found.")
            return False

    def extract_failed_ip(self, line):
        failed_log = line.strip()
        result = failed_log.partition("from")
        ip_part = result[2].strip()
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', ip_part)
        
        if ip_match:
            ip = ip_match.group()
            self.failed_ip_counts[ip] = self.failed_ip_counts.get(ip, 0) + 1
            self.failed_count += 1

    def extract_successful_login(self, line):
        line_lower = line.lower()
        ip_match = re.search(r'\b(?:from|for .*? from) ([\d\.]+)', line_lower)
        user_match = re.search(r'for (\w+)', line_lower)
        ip = ip_match.group(1) if ip_match else "unknown"
        user = user_match.group(1) if user_match else "unknown"
        self.successful_logins.append((ip, user))
        self.success_count += 1

    def get_suspicious_ips(self):
        sorted_ips = sorted(self.failed_ip_counts.items(), key=lambda x: x[1], reverse=True)
        print("Suspicious IPs (failed attempts):")
        for ip, count in sorted_ips:
            status = "Investigate" if count >= self.max_attempts else "Low risk"
            print(f"   {ip} -> {count} attempts ({status})")
        return sorted_ips
    
    def get_successful_logins(self):
        print("\nSuccessful logins:")
        for ip, user in self.successful_logins:
            print(f"   User '{user}' logged in from {ip}")
        return self.successful_logins

analyser = AnalysisOfLogFile()
success = analyser.analyse(log_file)
if success:
    analyser.get_suspicious_ips()
    analyser.get_successful_logins()
else:
    print()
    print("Analysis stopped due to missing file.")