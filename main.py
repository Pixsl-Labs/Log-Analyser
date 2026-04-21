# source venv/bin/activate

log_file = input("Please enter the file name that you would like to analyse: ")

failed_count = 0

with open(log_file, 'r') as file:
    for line in file:
        if "failed password" in line.lower():
            print(line.strip())
            failed_count += 1

if failed_count > 2:
    print("There is something suspicious and you should look into it!")

if failed_count > 5:
    print("Suspicious activity detected!")
