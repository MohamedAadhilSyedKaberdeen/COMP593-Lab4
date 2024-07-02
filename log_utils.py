import re
import csv

def get_file_path_from_cmd_line(param_num=1):
    import sys
    if len(sys.argv) < param_num + 1:
        print(f'Error: Missing log file path expected as command line parameter {param_num}.')
        sys.exit('Script execution aborted')

    log_path = sys.argv[param_num]

    if not os.path.isfile(log_path):
        print(f'Error: "{log_path}" is not the path of an existing file.')
        sys.exit('Script execution aborted')

    return log_path

def tally_port_traffic(log_path):
    port_counts = {}
    with open(log_path, 'r') as f:
        for line in f:
            port_match = re.search(r'DPT=(\d+)', line)
            if port_match:
                port = int(port_match.group(1))
                if port in port_counts:
                    port_counts[port] += 1
                else:
                    port_counts[port] = 1
    return port_counts

def generate_port_traffic_report(log_path, port_number):
    records = []
    with open(log_path, 'r') as f:
        for line in f:
            if f'DPT={port_number}' in line:
                records.append(line.strip())

    with open(f'destination_port_{port_number}_report.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(records)

def generate_invalid_user_report(log_path):
    records = []
    with open(log_path, 'r') as f:
        for line in f:
            if 'invalid user' in line:
                records.append(line.strip())

    with open('invalid_users.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(records)

def generate_source_ip_log(log_path, ip_address):
    records = []
    with open(log_path, 'r') as f:
        for line in f:
            if f'SRC={ip_address}' in line:
                records.append(line.strip())

    with open(f'source_ip_{ip_address.replace(".", "_")}.log', 'w') as f:
        f.write('\n'.join(records))
