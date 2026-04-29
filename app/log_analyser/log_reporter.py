from app.log_analyser.log_analyser import LogAnalyser
from app.config import MAX_ATTEMPTS

class LogReporter:
    def __init__(self, analyser):
        self.analyser: LogAnalyser = analyser

    def get_total_failed_login_attempts(self):
        total = sum(self.analyser.failed_ip_counts.values())
        return total

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
        for ip, user, _ in self.analyser.failed_logins:
            print(f"   User '{user}' failed login from {ip}")

    def get_successful_logins(self):
        if not self.analyser.successful_logins:
            return

        print("Successful logins:")
        for ip, user in self.analyser.successful_logins:
            print(f"   User '{user}' logged in from {ip}")

    def get_total_successful_login_attempts(self):
        total = len(self.analyser.successful_logins)
        return total

    def get_total_number_of_unique_ip_addresses(self):
        all_ips = set()

        for ip, _, _ in self.analyser.failed_logins:
            all_ips.add(ip)

        for ip, _ in self.analyser.successful_logins:
            all_ips.add(ip)

        return all_ips

    def detect_bruteforce(self, threshold=5, window_seconds=10):
        ip_attempts = self.analyser.group_attempts_by_ip()
        results = []

        for ip, time_stamps in ip_attempts.items():
            time_stamps.sort()

            for i in range(len(time_stamps) - threshold + 1):
                start = time_stamps[i]
                end = time_stamps[i + threshold - 1]

                diff = (end - start).seconds

                if diff <= window_seconds:
                    results.append((ip, threshold, diff))
                    break
                
        return results
    
    def get_brute_force_results(self):
        results = self.detect_bruteforce()

        if not results:
            print("No brute force activity detected")
            return
        
        print("Brute force detected:\n")

        for ip, threshold, diff in results:
            print(f"   {ip} -> {threshold} attempts in {diff}s (threshold={threshold})")

    def most_targeted_user(self):
        user_counts = {}

        for ip, user, _ in self.analyser.failed_logins:
            user_counts[user] = user_counts.get(user, 0) + 1

        sorted_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)

        return sorted_users

    def get_most_targeted_user(self):
        sorted_users = self.most_targeted_user()

        print("Most targeted users:")
        for user, count in sorted_users:
            print(f"   {user} -> {count} attempts")

    def detect_suspicious_success(self):
        failed_ips = set(ip for ip, _, _ in self.analyser.failed_logins)

        print("IPs with success after failure")
        for ip, user in self.analyser.successful_logins:
            if ip in failed_ips:
                print(f"   {ip} successfully logged in after failures")




    def export_report(self, filename):
        with open(filename, "w") as f:
            f.write("---Log Analysis Report---\n\n")

            if not self.analyser.failed_logins and not self.analyser.successful_logins:
                f.write("Log file contained no relevant login activity.\n\n")
            
            f.write("---Needs Attention!---\n\n")

            # Unique IPs
            all_ips = self.get_total_number_of_unique_ip_addresses()
            f.write(f"Unique IPs: {len(all_ips)}\n\n")

            # Suspicious IPs
            if self.analyser.failed_ip_counts:
                sorted_ips = sorted(self.analyser.failed_ip_counts.items(), key=lambda x: x[1], reverse=True)
                f.write("Suspicious IPs (failed attempts)\n")
                
                for ip, count in sorted_ips:
                    status = "Investigate" if count >= MAX_ATTEMPTS else "Low risk"
                    f.write(f"   {ip} -> {count} attempts ({status})\n")

                f.write("\n")
            else:
                f.write("No suspicious IPs found.\n")
            
            # Failed Logins
            if self.analyser.failed_logins:
                f.write("Failed logins:\n")
                for ip, user, _ in self.analyser.failed_logins:
                    f.write(f"   User '{user}' failed login from {ip}\n")

                f.write("\n")
            else:
                f.write("No failed logins found.\n")

            # Brute-force results
            results = self.detect_bruteforce()
            if results:
                f.write("Brute force detected:\n")

                for ip, threshold, diff in results:
                    f.write(f"   {ip} -> {threshold} attempts in {diff}s (threshold={threshold})\n")
            else:
                f.write("No brute force detected\n")

            # Most Targeted users
            sorted_users = self.most_targeted_user()

            if sorted_users:
                f.write("\nMost targeted users:\n")
                
                for user, count in sorted_users:
                    f.write(f"   {user} -> {count} attempts\n")
            else:
                f.write("\nNo targeted users found.\n")

            # Suspicious success
            failed_ips = set(ip for ip, _, _ in self.analyser.failed_logins)
            found = False
            f.write("IPs with success after failure:\n")
            
            for ip, user in self.analyser.successful_logins:
                if ip in failed_ips:
                    if not found:
                        f.write("IPs with success after failure:\n")
                        found = True
                    f.write(f"   {ip} successfully logged in after failures\n")

            if not found:
                f.write("No suspicious success detected.\n")

            f.write("\n---Standard Logins---\n\n")

            # Total Successful login attempts
            total_ = self.get_total_successful_login_attempts()
            f.write(f"Total number of successful logins: {total_}\n")

            # Successful logins
            if self.analyser.successful_logins:
                f.write("\nSuccessful logins:\n")
                for ip, user in self.analyser.successful_logins:
                    f.write(f"   User '{user}' logged in from {ip}\n")
            else:
                f.write("\nNo successful logins found.\n")

            
            if not self.analyser.failed_logins and not self.analyser.successful_logins:
                f.write("Log file contained no relevant login activity.\n\n")