# audit_script.py
from colorama import Fore, Style, init
init(autoreset=True)

def analyze_router_config(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()

    report_lines = []
    print("\n🔍 " + Fore.CYAN + "Router Configuration Audit Report\n" + "-" * 45)

    for line in lines:
        line = line.strip()
        if line.startswith("enable password"):
            msg = "Found enable password (should be encrypted or replaced with 'enable secret')."
            print(Fore.RED + "⚠️  " + msg)
            report_lines.append(msg)
        elif "password" in line and "enable password" not in line:
            msg = f"User password found: {line}"
            print(Fore.YELLOW + "🔐  " + msg)
            report_lines.append(msg)
        elif "no shutdown" in line:
            msg = "Interface is active (no shutdown)."
            print(Fore.GREEN + "✅  " + msg)
            report_lines.append(msg)
        elif "shutdown" in line:
            msg = "Interface is administratively down."
            print(Fore.RED + "🚫  " + msg)
            report_lines.append(msg)
        elif "transport input telnet" in line:
            msg = "Telnet is enabled (use SSH instead)."
            print(Fore.RED + "⚠️  " + msg)
            report_lines.append(msg)
        elif "service password-encryption" in line:
            msg = "Password encryption is enabled."
            print(Fore.GREEN + "✅  " + msg)
            report_lines.append(msg)

    print("\n" + Fore.CYAN + "✅ Audit complete! Report saved to 'audit_report.txt'\n")

    # Save report to a text file
    with open("audit_report.txt", "w") as f:
        f.write("Router Configuration Audit Report\n" + "-"*45 + "\n")
        for line in report_lines:
            f.write(line + "\n")

if __name__ == "__main__":
    analyze_router_config("router_config.txt")
