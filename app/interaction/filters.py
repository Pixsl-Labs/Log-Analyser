import logging

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
    
def handle_filter_menu(
        reporter,
        title,
        show_all_function,
        ip_function,
        user_function
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
        print(f"\nFilter {title} by:")
        print("1. None")
        print("2. IP")
        print("3. User")
        print("4. Back")

        filter_choice = input("\nSelect filter (1-4): ").strip()

        if filter_choice == "1":
            show_all_function()
            break

        elif filter_choice == "2":
            reporter.print_all_ips()

            ip = input("\nEnter IP address: ").strip()

            if not ip:
                print("\nNo IP entered.")
                continue

            ip_function(ip)
            break

        elif filter_choice == "3":
            reporter.print_all_usernames()

            username = input("\nEnter username: ").strip()

            if not username:
                print("\nNo username entered.")
                continue

            user_function(username)
            break

        elif filter_choice == "4":
            break

        else:
            print(f"\n'{filter_choice}' is an invalid choice. Please try again.")