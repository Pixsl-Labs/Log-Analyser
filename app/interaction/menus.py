from colorama import Fore


def display_log_analysis_menu() -> None:
    """
    Prints the display menu for Log Analysis

    Returns:
        None
    """

    print(
        Fore.GREEN
        + "\n=== Log Analysis Menu ===\n"
    )

    print("1. Show full report")
    print("2. Show attack summary")
    print("3. Show attack statistics")

    print(
        Fore.CYAN
        + "\n=== Investigation ===\n"
    )

    print("4. Show activity timeline")
    print("5. Show suspicious activity")
    print("6. Show failed login details")

    print(
        Fore.CYAN
        + "\n=== Detection ===\n"
    )

    print("7. Show suspicious IPs")
    print("8. Show brute force detection")
    print("9. Show most targeted users")
    print("10. Show suspicious success")
    print("11. Show user-targeted attacks")

    print(
        Fore.CYAN
        + "\n=== General Information ===\n"
    )

    print("12. Show successful logins")
    print("13. Show total failed logins")
    print("14. Show unique IP count")

    print(
        Fore.CYAN
        + "\n=== Configuration ===\n"
    )

    print("15. Export report to file")
    print("16. Analyse new file")
    print("17. Configure settings")
    print("18. Show current configuration")
    print("19. Exit")

    print(
        Fore.MAGENTA
        + "\n=== End of Menu ==="
    )

def display_configuration_menu(threshold: int, window_seconds: int) -> None:
    """
    Prints the configuration menu for alerations to Log Analysis
    
    Returns:
        None
    """
    print(
        Fore.GREEN
        + "\n=== Configuration Menu ===\n"
    )

    print(f"1. Maximum number of attempts (current = {threshold})")
    print(f"2. Maximum time window (current = {window_seconds})")
    print("3. Convert back to original")
    print("4. Exit")

    print(
        Fore.MAGENTA
        + "\n=== End of Menu === "
    )

def current_config(threshold: int, window_seconds: int) -> None:
    """
    Prints the current configurations
    
    Returns:
        None
    """
    print(
    Fore.CYAN
    + "\n" + "-" * 37
    )

    print(
        Fore.GREEN
        + "\n=== Current Configuration ===\n"
    )

    print(f"- Threshold: {threshold}")
    print(f"- Time window: {window_seconds}")

    print(
        Fore.MAGENTA
        + "\n=== End of Configuration Settings ===\n"
    )

    print(
    Fore.CYAN
    + "-" * 37
    )