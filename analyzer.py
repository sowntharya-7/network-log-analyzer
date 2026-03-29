import sys

def parse_logs(file_name):
    logs = []
    with open(file_name,'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 2:
                ip,status = parts
                logs.append((ip,status))
    return logs


def count_requests(logs):
    request_count = {}
    for ip, _ in logs:
        request_count[ip] = request_count.get(ip,0) + 1
    return request_count

def count_failures(logs):
    failure_count = {}
    for ip,status in logs:
        if status == "failed":
            failure_count[ip] = failure_count.get(ip,0) +1
    return failure_count

def find_suspicious(failures,threshold=2):
    return[ip for ip,count in failures.items() if count >= threshold]


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py log.txt")
        return
    file_name = sys.argv[1]

    logs = parse_logs(file_name)
    requests= count_requests(logs)
    failures = count_failures(logs)
    suspicious_ips = find_suspicious(failures)

    print("\n--- Network Summary ---")
    print(f"total request: {len(logs)}\n")

    print("Top IPs:")
    for ip,count in requests.items():
        print(f"{ip} -> {count} requests")

    print("\n Failures:")
    for ip,count in failures.items():
        print(f"{ip} -> {count} failures")
    
    print("\n Suspicious IPs:")
    for ip in suspicious_ips:
        print(ip)
if __name__ =="__main__":
    main()