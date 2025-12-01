# auditor.py
from netmiko import ConnectHandler
from colorama import Fore, init
import json
from datetime import datetime

init(autoreset=True)

# --------------------------
# FETCH CONFIG FROM VYOS
# --------------------------
def fetch_config():
    device = {
        "device_type": "vyos",
        "host": "192.168.56.10",    # your VyOS host-only IP
        "username": "admin",
        "password": "admin123",
    }

    print(Fore.CYAN + "[+] Connecting to router...")

    try:
        conn = ConnectHandler(**device)
        config = conn.send_command("show configuration commands")
        conn.disconnect()
        print(Fore.GREEN + "[+] Successfully fetched router configuration!")
        return config

    except Exception as e:
        print(Fore.RED + "[ERROR] SSH connection failed:", str(e))
        exit()


# --------------------------
# ANALYZE CONFIG
# --------------------------
def analyze_config(config_text):
    findings = []

    # Weak plaintext user passwords
    if "plaintext-password" in config_text:
        findings.append({
            "severity": "HIGH",
            "message": "Plaintext user password found.",
            "recommendation": "Use encrypted-password instead of plaintext-password."
        })

    # Telnet check (VyOS often does NOT support telnet)
    if "service telnet" in config_text:
        findings.append({
            "severity": "HIGH",
            "message": "Telnet service is enabled (INSECURE).",
            "recommendation": "Disable Telnet: delete service telnet"
        })

    # SSH check
    if "set service ssh" not in config_text:
        findings.append({
            "severity": "MEDIUM",
            "message": "SSH is not enabled.",
            "recommendation": "Enable SSH: set service ssh"
        })
    else:
        findings.append({
            "severity": "INFO",
            "message": "SSH is enabled.",
            "recommendation": "No action needed."
        })

    # Interface up/down detection
    if "disable" in config_text:
        findings.append({
            "severity": "LOW",
            "message": "One or more interfaces are disabled.",
            "recommendation": "Enable interfaces only if needed."
        })

    return findings


# --------------------------
# SAVE REPORTS
# --------------------------
def save_reports(findings):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Save text report
    with open("audit_report.txt", "w") as f:
        f.write("Router Security Audit Report\n")
        f.write("----------------------------------------\n")
        f.write(f"Generated at: {timestamp}\n\n")
        for item in findings:
            f.write(f"[{item['severity']}] {item['message']}\n")
            f.write(f"  Recommendation: {item['recommendation']}\n\n")

    # Save JSON report
    with open("audit_report.json", "w") as f:
        json.dump(findings, f, indent=4)

    print(Fore.GREEN + "[+] Reports saved: audit_report.txt & audit_report.json")


# --------------------------
# MAIN FUNCTION
# --------------------------
def main():
    config = fetch_config()
    findings = analyze_config(config)
    
    print("\n" + Fore.CYAN + "=== AUDIT RESULTS ===")
    for f in findings:
        color = Fore.RED if f["severity"] == "HIGH" else \
                Fore.YELLOW if f["severity"] == "MEDIUM" else \
                Fore.GREEN
        print(color + f"[{f['severity']}] " + f["message"])

    save_reports(findings)


if __name__ == "__main__":
    main()
