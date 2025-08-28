#!/usr/bin/env python3
import os
import sys
import json

def remove_extra_monitors_in_place(folder_name: str, monitor_id_threshold: int) -> None:
    """
    Removes entries with monitor_id greater than monitor_id_threshold from all JSON files in a folder.
    Modifies the files in place instead of creating a copy.
    """
    if not os.path.isdir(folder_name):
        print(f"Error: The folder '{folder_name}' does not exist.")
        sys.exit(1)

    for file_name in os.listdir(folder_name):
        if file_name.lower().endswith(".json"):
            file_path = os.path.join(folder_name, file_name)
            try:
                with open(file_path, 'r', encoding='utf-8') as infile:
                    raw_data = infile.read().strip()
                merged_data = raw_data.replace('][', ',')
                data = json.loads(merged_data)

                if not isinstance(data, list):
                    print(f"Warning: '{file_name}' is not a top-level JSON list. Skipping.")
                    continue

                cleaned_data = []
                for item in data:
                    if "monitor_id" in item and isinstance(item["monitor_id"], str) and item["monitor_id"].startswith("M"):
                        try:
                            numeric_id = int(item["monitor_id"][1:])
                            if numeric_id <= monitor_id_threshold:
                                cleaned_data.append(item)
                        except ValueError:
                            print(f"Warning: '{item['monitor_id']}' is malformed. Skipping entry.")

                with open(file_path, 'w', encoding='utf-8') as outfile:
                    json.dump(cleaned_data, outfile, indent=2)

                print(f"Processed '{file_name}': Kept {len(cleaned_data)} out of {len(data)} entries.")
            except json.JSONDecodeError as e:
                print(f"Error: Invalid JSON in '{file_name}'. Skipping. ({e})")
            except Exception as e:
                print(f"Unexpected error processing '{file_name}': {e}")

def compute_largest_converge_time_in_file(json_path: str) -> float:
    """
    Reads a JSON file (list of objects) and returns
    the largest converge_time found for entries with entity_type == 'Logger'.
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, list):
            return 0.0
        max_time = 0.0
        for entry in data:
            if entry.get("entity_type") == "Logger":
                ctime = entry.get("converge_time")
                if ctime is not None:
                    try:
                        val = float(ctime)
                        if val > max_time:
                            max_time = val
                    except (ValueError, TypeError):
                        pass
        return max_time
    except (FileNotFoundError, json.JSONDecodeError):
        return 0.0
    except Exception as e:
        print(f"Warning: Could not process '{json_path}': {e}", file=sys.stderr)
        return 0.0

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <folder_name> <monitor_id_threshold>")
        sys.exit(1)

    folder_name = sys.argv[1]
    try:
        monitor_id_threshold = int(sys.argv[2])
    except ValueError:
        print("Error: The threshold must be an integer.")
        sys.exit(1)

    # Step 1: Clean JSON files in place
    remove_extra_monitors_in_place(folder_name, monitor_id_threshold)

    # Step 2: Compute largest converge_time from cleaned data
    found_any_json = False
    for file_name in os.listdir(folder_name):
        if file_name.lower().endswith(".json"):
            found_any_json = True
            json_path = os.path.join(folder_name, file_name)
            largest_ctime = compute_largest_converge_time_in_file(json_path)
            print(f"{file_name}: {largest_ctime:.3f}")

    if not found_any_json:
        print(f"No .json files found in '{folder_name}'.")

if __name__ == "__main__":
    main()