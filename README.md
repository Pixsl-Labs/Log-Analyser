# Log Analyser

Analyse log files in order to extract any unsuccessful login attempts or successful logins. Returning any detected failed attempts with the associated IP address and number of failed attempts by that IP address. As well as returning all successful login attempts linking it to which user was successfully logged in with adn the associated IP address.

The program can either be ran as normal by running the main.py Python file or can be ran by entering `python3 main.py <log_file_to_be_analysed>`.

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
python3 main.py <log_file_for_analysis>
```

Or can be ran using the `F5` key, running a json launch file.

# Usage

1. Analyse logs to find out any failed login attempts, revealing the IP address used

# Goal

Analyse system logs and detect suspicious activity (e.g. failed login)

# Future Ideas

Expand into SOC-style detection tool

# References / Resources Used

https://www.codecademy.com/article/command-line-arguments-in-python
