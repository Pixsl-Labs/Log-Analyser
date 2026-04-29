# Log Analyser

Analyse log files in order to extract any unsuccessful login attempts or successful logins. Returning any detected failed attempts with the associated IP address and number of failed attempts by that IP address. As well as returning all successful login attempts linking it to which user was successfully logged in with and the associated IP address.

The program can either be ran as normal by running the main.py Python file or can be ran by entering `python3 main.py <log_file_to_be_analysed>` -> (needs updating!).

# Features

- Detect failed login attempts
- Identify suspicious IPs
- Detect brute-force attacks (time-based)
- Identify most targeted users
- Detect successful logins after failures
- Export analysis report to file

# Building the Project

1. **Clone the repository**

```
git clone https://github.com/Pixsl-Labs/Log-Analyser.git
cd <repsitory_folder>
```

2. **Create a virtual environment**

```
python -m venv venv
```

```
venv\Scripts\activate # Windows
```

```
source venv/bin/activate # Linux/Mac
```

3. **Install dependencies**

```
pip install -r requirements.txt
```

4. **Run the application**

```
python3 app.main.py <log_file_for_analysis>
```

Or can be ran using the `F5` key, running a json launch file.

# Usage

## Log Analyser

All of the below information can be found through the `Log Analysis Menu`, where the user can either select a full report of the log file or can find out specific information based on their requirement.

```
--- Log Analysis Menu ---
1. Show full report
2. Show total failed logins
3. Show suspicious IPs
4. Show failed login details
5. Show successful logins
6. Show unique IP count
7. Show brute force detection
8. Show targeted users
9. Show suspicious success
10. Export report to file
11. Analyse new file
12. Exit
```

Analyse a `.log` file to find out the following information:
   1. Number of unique IP address found
   2. Total number of failed login attempts
   3. Lists out suspicious IP address which have failed to logged into a user. Revealing the IP address, number of attempts and level of risk associated with that IP address
   4. Lists out all of the failed login attempts, with information on which user and from which IP address
   5. Total number of successful login attempts
   6. List of successful logins, listing the user that was logged into and from which IP address
   7. List of potential brute-forcing, listing the IP address, number of attempts within a timeframe and showing the threshold set to class it as brute-forcing
   8. Lists the most targeted users in order, with the user and number of attempts
   9. Lists all of the IP addresses which have successfully logged in after failing multiple times
   10. Allows the user to export the report to a `.txt` file with a custom filename
   11. Allows the user to select a new `.log` file for analysis
   12. Allows the user to exit by entering the number `8`

# Goal

Analyse system logs and detect suspicious activity (e.g. failed login, brute-force attempts)

# Future Ideas

Expand into SOC-style detection tool

# References / Resources Used

https://www.codecademy.com/article/command-line-arguments-in-python
