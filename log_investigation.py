import csv
import log_analysis_lib

# Get the log file path from the command line
log_path = log_analysis_lib.get_file_path_from_cmd_line()

def main():
    # Determine how much traffic is on each port
    port_traffic = tally_port_traffic()

    # Per step 9, generate reports for ports that have 100 or more records
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(port)

    # Generate report of invalid user login attempts
    generate_invalid_user_report()

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic():
    """Produces a dictionary of destination port numbers (key) that appear in a 
    specified log file and a count of how many times they appear (value)

    Returns:
        dict: Dictionary of destination port number counts
    """
    port_counts = {}
    records = log_analysis_lib.get_records_with_regex(log_path, r'DPT=(\d+)')
    for record in records:
        port = int(record.search(r'DPT=(\d+)', record).group(1))
        if port in port_counts:
            port_counts[port] += 1
        else:
            port_counts[port] = 1
    return port_counts

def generate_port_traffic_report(port_number):
    """Produces a CSV report of all network traffic in a log file for a specified 
    destination port number.

    Args:
        port_number (str or int): Destination port number
    """
    records = log_analysis_lib.get_records_with_regex(log_path, r'DPT={}'.format(port_number))
    with open('destination_port_{}_report.csv'.format(port_number), 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Date', 'Time', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port'])
        for record in records:
            parts = record.split()
            date = parts[0]
            time = parts[1]
            src_ip = re.search(r'SRC=(\S+)', record).group(1)
            dst_ip = re.search(r'DST=(\S+)', record).group(1)
            src_port = re.search(r'SPT=(\d+)', record).group(1)
            dst_port = re.search(r'DPT=(\d+)', record).group(1)
            writer.writerow([date, time, src_ip, dst_ip, src_port, dst_port])

def generate_invalid_user_report():
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.
    """
    records = log_analysis_lib.get_records_with_regex(log_path, r'invalid user')
    with open('invalid_users.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Date', 'Time', 'Username', 'IP Address'])
        for record in records:
            parts = record.split()
            date = parts[0]
            time = parts[1]
            username = re.search(r'Invalid user (\S+)', record).group(1)
            ip_address = re.search(r'from (\S+)', record).group(1)
            writer.writerow([date, time, username, ip_address])

def generate_source_ip_log(ip_address):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    records = log_analysis_lib.get_records_with_regex(log_path, r'SRC={}'.format(ip_address))
    with open('source_ip_{}.log'.format(ip_address.replace('.', '_')), 'w') as f:
        f.write('\n'.join(records))

if __name__ == "__main__":
    main()
