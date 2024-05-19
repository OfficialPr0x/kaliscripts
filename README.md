Here is a catchy and eye-appealing README for your script, complete with ASCII art:

```markdown
# Ultimate Ethical Hacking Tool

```plaintext
============================================                                  
                       $$$$$$\              
                      $$$ __$$\             
   $$$$$$\   $$$$$$\  $$$$\ $$ |$$\   $$\   
  $$  __$$\ $$  __$$\ $$\$$\$$ |\$$\ $$  |  
  $$ /  $$ |$$ |  \__|$$ \$$$$ | \$$$$  /   
  $$ |  $$ |$$ |      $$ |\$$$ | $$  $$<    
  $$$$$$$  |$$ |      \$$$$$$  /$$  /\$$\   
  $$  ____/ \__|       \______/ \__/  \__|  
  $$ |                                      
  $$ |                                      
  \__|                                      
                                            
      Ultimate Ethical Hacking Tool         
============================================
```

## Overview

The Ultimate Ethical Hacking Tool is a comprehensive and user-friendly script designed to streamline various aspects of penetration testing. With a plethora of features, this tool can handle everything from system setup and reconnaissance to exploitation and post-exploitation, including MiTM attacks and password hash capturing.

## Features

- **System Setup and Updates**
  - Update and upgrade the system
  - Install all required tools and dependencies

- **Reconnaissance**
  - Nmap Recon
  - Masscan Recon
  - Amass Recon
  - Maltego Recon
  - Social Analyzer Recon
  - DNSRecon
  - DNSEnum

- **Enumeration**
  - Enum4Linux Enumeration
  - SMBClient Enumeration
  - NBScan Enumeration
  - LDAP Enumeration
  - SNMP Enumeration
  - DNSRecon Enumeration
  - DNSEnum Enumeration

- **Vulnerability Analysis**
  - Nikto Vulnerability Analysis
  - ZAP Vulnerability Analysis
  - SQLMap Vulnerability Analysis
  - OpenVAS Vulnerability Analysis
  - Nessus Vulnerability Analysis

- **Exploitation**
  - Metasploit Exploitation
  - SQLMap Exploitation
  - BurpSuite Exploitation
  - ExploitDB Search
  - Fuzzing

- **Post-Exploitation**
  - Bloodhound Post-Exploitation
  - Mimikatz Post-Exploitation
  - Empire Post-Exploitation

- **MiTM Attacks**
  - Ettercap MiTM Attack
  - mitmproxy MiTM Attack
  - Responder MiTM Attack

- **Password Hash Capturing**
  - Responder Hash Capturing
  - Ettercap Hash Capturing
  - CredSniper Hash Capturing

- **Reporting**
  - Generate comprehensive reports

## Installation

### Prerequisites

Ensure you have the following tools installed on your system:

- Nmap
- Masscan
- Amass
- DNSRecon
- Nikto
- OWASP ZAP
- Enum4linux
- smbclient
- nbtscan
- ldap-utils
- snmp
- snmpwalk
- sqlmap
- OpenVAS
- Nessus
- Metasploit
- BurpSuite
- searchsploit
- afl
- bloodhound
- mimikatz
- Empire
- ettercap
- mitmproxy
- responder
- CredSniper

### Installation Commands

##
On a Debian-based system, you can install these tools using the following commands:
sudo apt update
sudo apt install -y nmap masscan amass dnsrecon nikto zaproxy enum4linux smbclient nbtscan ldap-utils snmp snmpwalk sqlmap openvas nessus metasploit-framework bloodhound

##
Download and install OWASP ZAP:
wget -O /opt/zap/ZAP_2_9_0.zip 'https://github.com/zaproxy/zaproxy/releases/download/v2.9.0/ZAP_2_9_0.zip'
unzip /opt/zap/ZAP_2_9_0.zip -d /opt/zap

##
Download and install BurpSuite:
mkdir -p /opt/BurpSuite
wget -O /opt/BurpSuite/BurpSuite.jar 'https://portswigger.net/burp/releases/download?product=community&version=2021.10.1&type=jar'


## Usage

1. **Run the script as root:**

   sudo ./ultimate_hacking_tool.sh
 

2. **Navigate through the menu and select the desired options:**

   ============================================
        Choose an option from the menu:
   ============================================
                  +--------------------------------------+
                  | 1. System Setup and Updates          |
                  +--------------------------------------+
                  | 2. Reconnaissance                    |
                  +--------------------------------------+
                  | 3. Enumeration                       |
                  +--------------------------------------+
                  | 4. Vulnerability Analysis            |
                  +--------------------------------------+
                  | 5. Exploitation                      |
                  +--------------------------------------+
                  | 6. Post-Exploitation                 |
                  +--------------------------------------+
                  | 7. MiTM Attacks                      |
                  +--------------------------------------+
                  | 8. Password Hash Capturing           |
                  +--------------------------------------+
                  | 9. Reporting                         |
                  +--------------------------------------+
                  | 0. Exit                              |
                  +--------------------------------------+


3. **Follow the prompts to perform the selected actions.**

## Contribution

Feel free to contribute to the project by submitting issues, feature requests, or pull requests on the [GitHub repository](https://github.com/your-repo/ultimate_hacking_tool).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

With this tool, you'll be equipped to handle a wide range of penetration testing tasks efficiently and effectively. Happy hacking!
