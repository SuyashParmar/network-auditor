from netmiko import ConnectHandler
from colorama import Fore, init
import json
from datetime import datetime
import re

init(autoreset=True)

# FETCH CONFIG FROM VYOS ROUTER
def fetch_config():
    device = {
        "device_type": "vyos",
        "host": "192.168.56.10",        
        "username": "admin",
        "password": "admin123",
    }

    print(Fore.CYAN + "[+] Connecting to router...")

    try:
        conn = ConnectHandler(**device)
        config = conn.send_command("show configuration commands")
        conn.disconnect()
        print(Fore.GREEN + "[+] Successfully fetched router configuration!")

        # Save raw config for reference
        with open("running_config_vyos.txt", "w") as cf:
            cf.write(config)

        return config

    except Exception as e:
        print(Fore.RED + f"[ERROR] SSH connection failed: {e}")
        exit()

# ANALYZE CONFIG

def analyze_config(config_text):
    findings = []

    # 1. PLAINTEXT PASSWORD CHECK

    if "plaintext-password" in config_text:
        findings.append({
            "severity": "HIGH",
            "message": "Plaintext user password found.",
            "recommendation": "Use encrypted-password instead of plaintext-password."
        })

    # 2. TELNET USAGE CHECK
    if "set service telnet" in config_text:
        findings.append({
            "severity": "HIGH",
            "message": "Telnet service is enabled (INSECURE).",
            "recommendation": "Disable telnet: delete service telnet"
        })
    else:
        findings.append({
            "severity": "INFO",
            "message": "No Telnet service found (Good).",
            "recommendation": "No action needed."
        })

    # 3. SSH STATUS CHECK

    if "set service ssh" not in config_text:
        findings.append({
            "severity": "MEDIUM",
            "message": "SSH is NOT enabled.",
            "recommendation": "Enable SSH: set service ssh"
        })
    else:
        findings.append({
            "severity": "INFO",
            "message": "SSH is enabled.",
            "recommendation": "Good security practice."
        })

    # 4. DISABLED INTERFACES CHECK (VyOS uses keyword 'disable')
    disabled_ifaces = []
    for m in re.finditer(r"^set interfaces (\S+) (\S+) disable$", config_text, re.M):
        disabled_ifaces.append(f"{m.group(1)} {m.group(2)}")

    if disabled_ifaces:
        findings.append({
            "severity": "LOW",
            "message": "Interfaces disabled: " + ", ".join(disabled_ifaces),
            "recommendation": "Enable interfaces only if required."
        })
    else:
        findings.append({
            "severity": "INFO",
            "message": "No disabled interfaces found.",
            "recommendation": "All interfaces are active."
        })

    # 5. SECURITY SCORE 
  
    high_medium_count = sum(
        1 for f in findings if f["severity"] in ("HIGH", "MEDIUM")
    )

    score = max(0, 100 - high_medium_count * 10)

    findings.insert(0, {
        "severity": "INFO",
        "message": f"Security Score: {score}/100",
        "recommendation": "Fix HIGH and MEDIUM issues to improve score."
    })

    return findings


def save_reports(findings):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # TEXT REPORT  
    with open("audit_report.txt", "w") as f:
        f.write("Router Security Audit Report\n")
        f.write("----------------------------------------\n")
        f.write(f"Generated at: {timestamp}\n\n")

        # Print Security Score FIRST
        score_item = findings[0]
        f.write(f"[{score_item['severity']}] {score_item['message']}\n")
        f.write(f"  Recommendation: {score_item['recommendation']}\n\n")

        # Print remaining findings
        for item in findings[1:]:
            f.write(f"[{item['severity']}] {item['message']}\n")
            f.write(f"  Recommendation: {item['recommendation']}\n\n")

    #  JSON REPORT  
    with open("audit_report.json", "w") as f:
        json.dump(findings, f, indent=4)

    print(Fore.GREEN + "[+] Reports saved: audit_report.txt & audit_report.json")


# MAIN FUNCTION
def main():
    config = fetch_config()
    findings = analyze_config(config)

    print("\n" + Fore.CYAN + "=== AUDIT RESULTS ===\n")

    for f in findings:
        color = (
            Fore.RED if f["severity"] == "HIGH" else
            Fore.YELLOW if f["severity"] == "MEDIUM" else
            Fore.GREEN
        )
        print(color + f"[{f['severity']}] " + f["message"])

    save_reports(findings)


if __name__ == "__main__":
    main()