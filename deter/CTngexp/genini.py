def generate_ini_file(filename, ca_count, logger_count, monitor_count):
    sections = {
        "CA": [f"CA{i+1}" for i in range(ca_count)],
        "Logger": [f"Logger{i+1}" for i in range(logger_count)],
        "Monitor": [f"Monitor{i+1}" for i in range(monitor_count)],
        "control": ["Control"]
    }

    with open(filename, 'w') as file:
        for section, values in sections.items():
            file.write(f"[{section}]\n")
            for value in values:
                file.write(f"{value}\n")
            file.write("\n")  # Separate sections with a newline

    print(f"{filename} has been created successfully!")


if __name__ == "__main__":
    ca_count = int(input("Enter number of CAs: "))
    logger_count = int(input("Enter number of Loggers: "))
    monitor_count = int(input("Enter number of Monitors: "))

    generate_ini_file("inv.ini", ca_count, logger_count, monitor_count)
