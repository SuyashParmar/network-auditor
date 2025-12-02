Project Title: Network Device Security Auditor using Python & VyOS

📌 About This Project

In real networks, routers and switches must be secure.
If they have weak passwords, telnet enabled, or wrong settings, they can be hacked.

This project creates:
A virtual router using VyOS inside VMware/VirtualBox
A Python tool that connects to the router using SSH
Automatically checks for security issues
Creates a security report in .txt and .json formats
This project shows how to audit a router like a real network engineer.

🧰 Tools Used:
VyOS : Free virtual router OS for testing
VMware / VirtualBox : Runs VyOS as a virtual machine
Python : Used to write the auditor
Netmiko : Library to SSH into router
Colorama : Colored terminal output

📡 VyOS Network Setup

Inside VMware we created:
Adapter 1: NAT → For internet
Adapter 2: Host-Only → For Windows ↔ Router communication

VyOS configuration:
configure
set interfaces ethernet eth0 address dhcp
set interfaces ethernet eth1 address 192.168.56.10/24
set service ssh port 22
set system login user admin authentication plaintext-password "admin123"
commit
save
exit

🔌 Testing Connectivity from Windows:
Ping the Router on your terminal : ping 192.168.56.10
SSH into Router : ssh admin@192.168.56.10

🐍 Python Auditor Script
The Python script does the following:

✔ Connects to VyOS using SSH
✔ Downloads full router configuration
✔ Checks for:

Plaintext passwords
SSH enabled or not
Telnet usage
Disabled interfaces
Generates a Security Score

✔ Saves three files:
audit_report.txt
audit_report.json
running_config_vyos.txt

RUN THE SCRIPT: python auditor.py
