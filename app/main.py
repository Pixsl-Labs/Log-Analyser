import sys, argparse, os

# Allows running directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.interaction.interaction import Interaction

from app.log_analyser.log_analyser import LogAnalyser
from app.log_analyser.log_reporter import LogReporter

def run_cli(args):
    analyser = LogAnalyser()
    log_file = "log_files/" + args.file
    
    success = analyser.analyse(log_file)

    if success:
        reporter = LogReporter(analyser)

        if args.report:
            print("\n--- Log Analysis Report ---\n")
            print("--- Attention Needed! --- \n")

            report_steps = [
                reporter.print_suspicious_ips,
                reporter.print_brute_force_results,
                reporter.print_most_targeted_user,
                reporter.detect_suspicious_success,
                reporter.print_user_targeting
            ]

            for step in report_steps:
                step()
                print()
        else:
            interaction = Interaction(analyser, reporter)
            interaction.run()
    else:
        print("\nAnalysis stopped due to missing file.")

def run_interactive():
    print("Interaction mode\n")

    analyser = LogAnalyser()

    while True:
        file_name = input("Enter log file name (e.g. auth.log): ").strip()

        if file_name.lower() == "exit":
            print("Exiting...")
            return

        if not file_name:
            print("No file provided. Try again.\n")
            continue

        if not file_name.endswith(".log"):
            file_name += ".log"

        log_file = os.path.join("log_files", file_name)

        if not os.path.exists(log_file):
            print("File not found. Try again.\n")
            continue

        success = analyser.analyse(log_file)

        if success:
            break
        else:
            print("Failed to analyse file. Try again.\n")
    
    reporter = LogReporter(analyser)
    interaction = Interaction(analyser, reporter)

    interaction.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Analysis Tool")
    parser.add_argument("file", nargs="?", help="Path to log file")
    parser.add_argument("--report", action="store_true", help="Show full report")

    args = parser.parse_args()

    if args.file:
        run_cli(args)
    else:
        run_interactive()