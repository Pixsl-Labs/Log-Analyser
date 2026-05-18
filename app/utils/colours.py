from colorama import Fore


def get_severity_colour(
    severity: str
) -> str:

    if severity == "HIGH":
        return Fore.LIGHTRED_EX

    elif severity == "MEDIUM":
        return Fore.YELLOW
    
    elif severity == "LOW":
        return Fore.GREEN

    return Fore.WHITE


def get_status_colour(
    status: str
) -> str:

    if status.upper() == "FAILED":
        return Fore.LIGHTRED_EX

    elif status.upper() == "SUCCESS":
        return Fore.GREEN

    return Fore.WHITE

def get_attempt_colour(
    count: int
) -> str:
    
    if count >= 15:
        return Fore.LIGHTRED_EX
    
    elif count >= 10:
        return Fore.RED
    
    elif count >= 5:
        return Fore.LIGHTYELLOW_EX
    
    return Fore.LIGHTGREEN_EX