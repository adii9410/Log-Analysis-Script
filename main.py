import re
import csv
from collections import defaultdict

# Log analysis functions

def count_requests_per_ip(log_file):
    ip_requests = defaultdict(int)
    
    with open(log_file, 'r') as file:
        for line in file:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                ip_requests[ip] += 1
                
    return dict(sorted(ip_requests.items(), key=lambda x: x[1], reverse=True))

def most_frequently_accessed_endpoint(log_file):
    endpoint_requests = defaultdict(int)
    
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(r'\"(GET|POST) (.+?) HTTP/', line)
            if match:
                endpoint = match.group(2)
                endpoint_requests[endpoint] += 1
                
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])
    return most_accessed_endpoint

def detect_suspicious_activity(log_file, threshold=10):
    failed_login_attempts = defaultdict(int)
    
    with open(log_file, 'r') as file:
        for line in file:
            if '401' in line or 'Invalid credentials' in line:
                match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    failed_login_attempts[ip] += 1
                    
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > threshold}
    return suspicious_ips

def save_to_csv(ip_requests, most_accessed, suspicious_activity):
    with open('log_analysis_results.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        
        # Requests per IP section
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        
        # Most accessed endpoint section
        writer.writerow([])
        writer.writerow(['Most Frequently Accessed Endpoint:', most_accessed[0], 'Access Count:', most_accessed[1]])
        
        # Suspicious activity section
        writer.writerow([])
        writer.writerow(['Suspicious Activity Detected:'])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

# Main execution
if __name__ == "__main__":
    log_file = 'sample.log'
    
    # Count requests per IP
    ip_requests = count_requests_per_ip(log_file)
    print("IP Address           Request Count")
    for ip, count in ip_requests.items():
        print(f"{ip:20} {count}")
    
    # Most frequently accessed endpoint
    most_accessed = most_frequently_accessed_endpoint(log_file)
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(log_file)
    if suspicious_activity:
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:20} {count}")
    
    # Save results to CSV
    save_to_csv(ip_requests, most_accessed, suspicious_activity)
    print("\nResults saved to 'log_analysis_results.csv'")