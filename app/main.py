import re
import sys

from app.interaction.interaction import Interaction

from app.log_analyser.log_analyser import LogAnalyser
from app.log_analyser.log_reporter import LogReporter

if len(sys.argv) > 1:
    log_file = sys.argv[1]
else:
    log_file = input("Please enter the file name that you would like to analyse: ")

log_file = "log_files/" + log_file

if __name__ == "__main__":
    analyser = LogAnalyser()
    success = analyser.analyse(log_file)

    if success:
        reporter = LogReporter(analyser)
        interaction = Interaction(analyser, reporter)
        interaction.run()
    else:
        print("\nAnalysis stopped due to missing file.")