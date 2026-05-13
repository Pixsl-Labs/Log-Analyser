from datetime import datetime
from dataclasses import dataclass

@dataclass
class LogEntry:
    ip: str
    user: str
    timestamp: datetime
    status: str
    severity: str = "LOW"