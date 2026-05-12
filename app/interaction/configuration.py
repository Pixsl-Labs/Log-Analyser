from app.config import MAX_ATTEMPTS, TIME_WINDOW_SECONDS
from app.interaction.menus import display_configuration_menu
from app.interaction.filters import integer_validation

def configure(self) -> None:
    """
    Allows the user to configurate the current configuration settings.
    """
    while True:
        display_configuration_menu(self.threshold, self.window_seconds)
        print(f"\nCurrent config: threshold={self.threshold}, window={self.window_seconds}")
        choice = input("\nSelect option (1-4): ").strip()

        if choice == "1":
            new_value = integer_validation(
                f"\nEnter max attempts (current = {self.threshold}): ",
                self.threshold,
                label="threshold"
            )
            
            if new_value != self.threshold:
                self.threshold = new_value
                print("\nSettings Updated.")
        
        elif choice == "2":
            new_value = integer_validation(
                f"\nEnter time window (current = {self.window_seconds}): ",
                self.window_seconds,
                label="time window"
            )
            
            if new_value != self.window_seconds:
                self.window_seconds = new_value
                print("\nSettings Updated.")
        
        elif choice == "3":
            self.threshold = MAX_ATTEMPTS
            self.window_seconds = TIME_WINDOW_SECONDS

            print(f"\nConfigured settings have now been set back to default (threshold={self.threshold}, time window={self.window_seconds})")
        
        elif choice == "4":
            break

        else:
            print("\nInvalid choice. Please try again.")