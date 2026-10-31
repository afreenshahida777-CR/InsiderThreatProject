import pandas as pd

def analyze_logs():
    print("[*] Loading Insider Threat Dataset...")
    
    # Load logs
    login_df = pd.read_csv('data/login_logs.csv')
    endpoint_df = pd.read_csv('data/endpoint_logs.csv')
    transfer_df = pd.read_csv('data/transfer_logs.csv')
    
    print("\n--- UBA & PRIVILEGE ABUSE ALERTS ---")
    
    # Check for multiple failed logins followed by success (Brute Force / Credential Stuffing)
    failed_logins = login_df[login_df['login_status'] == 'FAILURE']
    if not failed_logins.empty:
        print("[!] ALERT: Multiple authentication failures detected:")
        for _, row in failed_logins.iterrows():
            print(f"    - User: {row['username']} | IP: {row['ip_address']} | Reason: {row['failure_reason']}")

    # Check for suspicious foreign location logins
    suspicious_loc = login_df[login_df['location'].str.contains('Foreign', case=False, na=False)]
    if not suspicious_loc.empty:
        print("\n[!] ALERT: Access from unusual/foreign location detected:")
        for _, row in suspicious_loc.iterrows():
            print(f"    - User: {row['username']} logged in from {row['ip_address']} ({row['location']})")

    print("\n--- DATA EXFILTRATION ALERTS ---")
    # Check for large data transfers
    large_transfers = transfer_df[transfer_df['file_size_mb'] > 400]
    if not large_transfers.empty:
        print("[!] ALERT: High-volume data exfiltration detected:")
        for _, row in large_transfers.iterrows():
            print(f"    - User: {row['username']} transferred {row['file_size_mb']} MB to {row['destination_ip']}")

if __name__ == '__main__':
    analyze_logs()