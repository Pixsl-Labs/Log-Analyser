import logging

from datetime import datetime, time

def integer_validation(
        prompt, 
        default, 
        label="value"
    ) -> int:
    """
    Prompts the user for an integer input.

    If the input is empty or invalid, returns the provided default value.

    Args:
        prompt (str): Input prompt to display to the user.
        default (int): Default value to use if input is invalid.
        label (str): Name of the value (for user messaging).

    Returns:
        int: Valid integer input or default value.
    """
    value = input(prompt).strip()

    if value == "":
        print(f"Using default {label} ({default})\n")
        return default
    
    try:
        return int(value)
    except ValueError:
        logging.error(f"Error: Invalid input, using default.")
        print(f"Using default {label} ({default})\n")
        return default
    
def get_time_range() -> tuple[time | None, time | None]:

    use_time_filter = input(
        "\nApply time range? (y/n): "
    ).strip().lower()

    if use_time_filter != "y":
        return None, None
    
    start = input(
        "Start time (HH:MM:SS) "
    ).strip()

    end = input(
        "End time (HH:MM:SS) "
    ).strip()

    try:

        start_time = (
            datetime.strptime(start, "%H:%M:%S").time()
            if start else None
        )

        end_time = (
            datetime.strptime(end, "%H:%M:%S").time()
            if end else None
        )

        return start_time, end_time
    
    except ValueError:

        logging.error(f"Error: Invalid time format, using default.")

        return None, None
    
def handle_filter_menu(
        reporter,
        title,
        show_function,
        filters
    ) -> None:
    """
    Handles reusable filtering menu for investigation features.
    
    Args:
        title (str): Menu title.
        show_all_function (callable): Function for showing all results.
        ip_function (callable): Function for IP filtering.
        user_function (callable): Function for username filtering.

    Returns:
        None
    """
    while True:

        print(f"\nFilter {title} by:\n")

        options = {}
        option_number = 1

        # Show all
        print(f"{option_number}. None")
        options[str(option_number)] = "none"
        option_number += 1

        # Dynamic filters
        for filter_name in filters:
            display_name = filter_name.upper() if filter_name == "ip" else filter_name.title()

            print(f"{option_number}. {display_name}")
            options[str(option_number)] = filter_name
            option_number += 1

        # Back
        print(f"{option_number}. Back")
        options[str(option_number)] = "back"

        choice = input("\nSelect option: ").strip()

        selected_filter = options.get(choice)

        if selected_filter == "none":
            start_time, end_time = get_time_range()

            show_function(
                start_time=start_time,
                end_time=end_time
            )

            break

        elif selected_filter == "ip":

            reporter.print_all_ips()

            ip = input("\nEnter IP address: ").strip()

            if not ip:
                print("\nNo IP entered.")
                continue

            start_time, end_time = get_time_range()

            show_function(
                ip=ip,
                start_time=start_time,
                end_time=end_time
            )

            break

        elif selected_filter == "username":

            reporter.print_all_usernames()

            username = input("\nEnter username: ").strip()

            if not username:
                print("\nNo username entered.")
                continue

            start_time, end_time = get_time_range()

            show_function(
                username=username,
                start_time=start_time,
                end_time=end_time
            )

            break

        elif selected_filter == "severity":

            severity = input(
                "\nEnter severity (LOW/MEDIUM/HIGH): "
            ).strip().upper()

            if not severity:
                print("\nNo severity entered.")
                continue

            start_time, end_time = get_time_range()

            show_function(
                severity=severity,
                start_time=start_time,
                end_time=end_time
            )

            break

        elif selected_filter == "status":

            status = input(
                "\nEnter status (SUCCESS/FAILED): "
            ).strip().upper()

            if not status:
                print("\nNo status entered.")
                continue

            start_time, end_time = get_time_range()

            show_function(
                status=status,
                start_time=start_time,
                end_time=end_time
            )

            break

        elif selected_filter == "back":
            break

        else:
            print(f"\n'{choice}' is an invalid choice.")