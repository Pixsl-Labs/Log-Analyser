import sys, argparse

from app.interaction.interaction import Interaction

from app.log_analyser.log_analyser import LogAnalyser
from app.log_analyser.log_reporter import LogReporter

parser = argparse.ArgumentParser(description="Log Analysis Tool")

parser.add_argument("file", help="Path to log file")
parser.add_argument("--report", action="store_true", help="Show full report")

args = parser.parse_args()

if __name__ == "__main__":
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