from app.reporting.statistics import Statistics
from app.reporting.detection import Detection
from app.reporting.investigation import Investigation
from app.reporting.exports import Export
from app.reporting.summary import Summary


class LogReporter(
    Statistics,
    Detection,
    Investigation,
    Export,
    Summary
):
    """
    Generates reports and summaries based on analysed log data.

    Responsible for:
    - Displaying login statistics
    - Detecting suspicious activity
    - Exporting reports to file
    """

    def __init__(self, analyser):
        self.analyser = analyser