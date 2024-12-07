import csv
import re
from collections import Counter, defaultdict

# Function to parse the log file
def parse_log(file_path):
    log_data = []
    with open(file_path, 'r') as file:
        for line in file:
            # Regular expression to parse log file entries
            match = re.match(
                r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"(?P<method>GET|POST) (?P<endpoint>/\S*).*" (?P<status>\d+)',
                line)
            if match:
                log_data.append(match.groupdict())
    return log_data

# Count requests per IP address
def count_requests_per_ip(log_data):
    ip_counter = Counter(entry['ip'] for entry in log_data)
    return ip_counter

# Identify the most frequently accessed endpoint
def most_frequent_endpoint(log_data):
    endpoint_counter = Counter(entry['endpoint'] for entry in log_data)
    most_common = endpoint_counter.most_common(1)
    return most_common[0] if most_common else None

# Detect suspicious activity
def detect_suspicious_activity(log_data, threshold=10):
    failed_logins = defaultdict(int)
    for entry in log_data:
        if entry['status'] == '401':
            failed_logins[entry['ip']] += 1
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    return suspicious_ips

# Save results to CSV
def save_to_csv(ip_counts, most_accessed, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)

        # Write requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])  # Blank line

        # Write most accessed endpoint
        writer.writerow(['Most Frequently Accessed Endpoint', 'Access Count'])
        if most_accessed:
            writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])  # Blank line

        # Write suspicious activity
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main function
def main():
    log_file = 'sample.log'
    output_file = 'log_analysis_results.csv'

    log_data = parse_log(log_file)

    # Analyze data
    ip_counts = count_requests_per_ip(log_data)
    most_accessed = most_frequent_endpoint(log_data)
    suspicious_ips = detect_suspicious_activity(log_data)

    # Display results
    print("IP Address           Request Count")
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20} {count}")

    if most_accessed:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    save_to_csv(ip_counts, most_accessed, suspicious_ips, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == '__main__':
    main()
