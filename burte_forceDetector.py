from collections import defaultdict
mock_auth_logs = [
    {"ip": "192.168.1.50", "user": "admin", "status": "failed"},
    {"ip": "192.168.1.50", "user": "admin", "status": "failed"},
    {"ip": "192.168.1.50", "user": "admin", "status": "failed"},
    {"ip": "192.168.1.50", "user": "admin", "status": "success"},
    {"ip": "10.0.0.99", "user": "user1", "status": "failed"},
    {"ip": "10.0.0.99", "user": "user2", "status": "failed"},
    {"ip": "10.0.0.99", "user": "user3", "status": "failed"},
]

def analyze_logs(logs, failure_threshold=3):
    """
    Parses logs to identify high-frequency authentication failures.
    """
    ip_failures = defaultdict(int)
    ip_targeted_users = defaultdict(set)

    for entry in logs:
        if entry["status"] == "failed":
            ip = entry["ip"]
            ip_failures[ip] += 1
            ip_targeted_users[ip].add(entry["user"])

    print("--- Security Analysis Report ---")
    for ip, count in ip_failures.items():
        if count >= failure_threshold:
            distinct_users = len(ip_targeted_users[ip])
            if distinct_users > 1:
                print(f"[ALERT] Potential Credential Stuffing detected from IP: {ip}")
                print(f"        Failed attempts: {count} across {distinct_users} different accounts.\n")
            else:
                print(f"[ALERT] Potential Brute Force detected from IP: {ip}")
                print(f"        Failed attempts: {count} targeting a single account.\n")

if __name__ == "__main__":
    analyze_logs(mock_auth_logs)
