import sys
import os
import re
import pandas as pd

def get_file_path_from_cmd_line(param_num=1):
    if len(sys.argv) < param_num + 1:
        print(f'Error: Missing log file path expected as command line parameter {param_num}.')
        sys.exit('Script execution aborted')

    log_path = os.path.abspath(sys.argv[param_num])

    if not os.path.isfile(log_path):
        print(f'Error: "{log_path}" is not the path of an existing file.')
        sys.exit('Script execution aborted')

    return log_path

def filter_log_by_regex(log_path, regex, ignore_case=True, print_summary=False, print_records=False):
    filtered_records = []
    captured_data = []

    search_flags = re.IGNORECASE if ignore_case else 0

    with open(log_path, 'r') as file:
        for record in file:
            match = re.search(regex, record, search_flags)
            if match:
                filtered_records.append(record.strip())
                if match.lastindex:
                    captured_data.append(match.groups())

    if print_records:
        print(*filtered_records, sep='\n', end='\n')

    if print_summary:
        print(f'The log file contains {len(filtered_records)} records that case-{"in" if ignore_case else ""}sensitive match the regex "{regex}".')

    return (filtered_records, captured_data)

def main():
    log_path = get_file_path_from_cmd_line()

    filtered_records, _ = filter_log_by_regex(log_path, 'sshd', print_summary=True, print_records=True)

    filtered_records, extracted_data = filter_log_by_regex(log_path, r'SRC=(.*?) DST=(.*?) LEN=(.*?)')
    extracted_df = pd.DataFrame(extracted_data, columns=('Source IP', 'Destination IP', 'Length'))
    extracted_df.to_csv('data.csv', index=False)

    print("Data has been extracted and saved to data.csv")

if __name__ == "__main__":
    main()