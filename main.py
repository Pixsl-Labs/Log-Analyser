# source venv/bin/activate
import re

log_file = input("Please enter the file name that you would like to analyse: ")

def analyse_logs(log_file):
    failed_count = 0
    ip_counts = {}
    max_attempts = 5

    with open(log_file, 'r') as file:
        for line in file:
            if "failed password" in line.lower():
                failed_log = line.strip()
                result = failed_log.partition("from")
                ip_part = result[2].strip()
                ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', ip_part)
                
                if ip_match:
                    ip = ip_match.group()
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                    failed_count += 1

    for ip, count in ip_counts.items():
        if count >= max_attempts:
            print(f"{ip} has tried {count} times! Please investigate into this IP: {ip}")
        else:
            print(f"{ip} has tried {count} times!")

    if failed_count > 5:
        print("High risk: multiple failed login attempts detected!")
    elif failed_count > 2:
        print("Warning: some failed login attempts detected.")

analyse_logs(log_file)