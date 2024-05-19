#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root."
  exit 1
fi

# Function to display ASCII art and menu
display_menu() {
  clear
  echo "============================================"
  echo "                                            "
  echo "                       $$$$$$\              "
  echo "                      $$$ __$$\             "
  echo "   $$$$$$\   $$$$$$\  $$$$\ $$ |$$\   $$\   "
  echo "  $$  __$$\ $$  __$$\ $$\$$\$$ |\$$\ $$  |  "
  echo "  $$ /  $$ |$$ |  \__|$$ \$$$$ | \$$$$  /   "
  echo "  $$ |  $$ |$$ |      $$ |\$$$ | $$  $$<    "
  echo "  $$$$$$$  |$$ |      \$$$$$$  /$$  /\$$\   "
  echo "  $$  ____/ \__|       \______/ \__/  \__|  "
  echo "  $$ |                                      "
  echo "  $$ |                                      "
  echo "  \__|                                      "
  echo "                                            "
  echo "      Ultimate Ethical Hacking Tool         "
  echo "============================================"
  echo
  echo "Choose an option from the diagram:"
  echo
  echo "               +--------------------------------------+"
  echo "               | 1. Update and upgrade system         |"
  echo "               +--------------------------------------+"
  echo "               | 2. Install general tools             |"
  echo "               +--------------------------------------+"
  echo "               | 3. Install recon tools               |"
  echo "               +--------------------------------------+"
  echo "               | 4. Install enumeration tools         |"
  echo "               +--------------------------------------+"
  echo "               | 5. Install exploitation tools        |"
  echo "               +--------------------------------------+"
  echo "               | 6. Install post-exploitation tools   |"
  echo "               +--------------------------------------+"
  echo "               | 7. Install defense tools             |"
  echo "               +--------------------------------------+"
  echo "               | 8. Install analytics tools           |"
  echo "               +--------------------------------------+"
  echo "               | 9. Setup UFW                         |"
  echo "               +--------------------------------------+"
  echo "               | 10. Setup Fail2Ban                   |"
  echo "               +--------------------------------------+"
  echo "               | 11. Setup Splunk                     |"
  echo "               +--------------------------------------+"
  echo "               | 12. Perform recon automation         |"
  echo "               +--------------------------------------+"
  echo "               | 13. Perform enumeration automation   |"
  echo "               +--------------------------------------+"
  echo "               | 14. Perform exploitation automation  |"
  echo "               +--------------------------------------+"
  echo "               | 15. Perform post-exploitation        |"
  echo "               +--------------------------------------+"
  echo "               | 16. Perform password cracking        |"
  echo "               +--------------------------------------+"
  echo "               | 17. Perform web application testing  |"
  echo "               +--------------------------------------+"
  echo "               | 18. Setup network analysis tools     |"
  echo "               +--------------------------------------+"
  echo "               | 19. Run vulnerability scanners       |"
  echo "               +--------------------------------------+"
  echo "               | 20. Post-exploitation and lateral    |"
  echo "               |     movement                         |"
  echo "               +--------------------------------------+"
  echo "               | 21. Advanced password cracking       |"
  echo "               +--------------------------------------+"
  echo "               | 0. Exit                              |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read choice
}

# Function to update and upgrade the system
update_system() {
  echo "[*] Updating and upgrading the system..."
  apt update && apt upgrade -y
}

# Function to install general tools
install_general_tools() {
  echo "[*] Installing general tools..."
  apt install -y git curl wget vim
}

# Function to install recon tools
install_recon_tools() {
  echo "[*] Installing recon tools..."
  apt install -y nmap masscan theHarvester recon-ng amass sublist3r dnsenum whois whatweb dirsearch
}

# Function to install enumeration tools
install_enum_tools() {
  echo "[*] Installing enumeration tools..."
  apt install -y enum4linux smbclient nbtscan
}

# Function to install exploitation tools
install_exploitation_tools() {
  echo "[*] Installing exploitation tools..."
  apt install -y metasploit-framework sqlmap
}

# Function to install post-exploitation tools
install_post_exploitation_tools() {
  echo "[*] Installing post-exploitation tools..."
  apt install -y bloodhound mimikatz
}

# Function to install defense tools
install_defense_tools() {
  echo "[*] Installing defense tools..."
  apt install -y ufw fail2ban
}

# Function to install analytics tools
install_analytics_tools() {
  echo "[*] Installing analytics tools..."
  apt install -y splunk
}

# Function to setup UFW
setup_ufw() {
  echo "[*] Installing and configuring UFW..."
  apt install ufw -y
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow ssh
  ufw allow http
  ufw allow https
  ufw logging on
  ufw enable
}

# Function to setup Fail2Ban
setup_fail2ban() {
  echo "[*] Installing and configuring Fail2Ban..."
  apt install fail2ban -y
  systemctl enable fail2ban
  systemctl start fail2ban
}

# Function to setup Splunk
setup_splunk() {
  echo "[*] Installing Splunk..."
  wget -O splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz 'https://download.splunk.com/products/splunk/releases/8.2.2/linux/splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz'
  tar -xvf splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz -C /opt
  /opt/splunk/bin/splunk start --accept-license
  /opt/splunk/bin/splunk enable boot-start
}

# Function to perform recon automation
recon_automation() {
  echo "[*] Enter the domain for recon:"
  read DOMAIN
  OUTPUT_DIR="recon-results/$DOMAIN"
  mkdir -p $OUTPUT_DIR

  echo "[*] Starting recon for $DOMAIN..."

  echo "[*] Running Amass for subdomain enumeration..."
  amass enum -d $DOMAIN -o $OUTPUT_DIR/amass.txt

  echo "[*] Running Sublist3r for subdomain enumeration..."
  sublist3r -d $DOMAIN -o $OUTPUT_DIR/sublist3r.txt

  echo "[*] Combining results..."
  cat $OUTPUT_DIR/amass.txt $OUTPUT_DIR/sublist3r.txt | sort -u > $OUTPUT_DIR/subdomains.txt

  echo "[*] Running DNS enumeration with dnsenum..."
  dnsenum $DOMAIN > $OUTPUT_DIR/dnsenum.txt

  echo "[*] Running whois lookup..."
  whois $DOMAIN > $OUTPUT_DIR/whois.txt

  echo "[*] Running WhatWeb for web technology fingerprinting..."
  whatweb -v $DOMAIN > $OUTPUT_DIR/whatweb.txt

  echo "[*] Running dirsearch for directory brute-forcing..."
  dirsearch -u $DOMAIN -e php,html,js,txt -o $OUTPUT_DIR/dirsearch.txt

  echo "[*] Recon completed for $DOMAIN. Results saved in $OUTPUT_DIR."
}

# Function to perform enumeration automation
enum_automation() {
  echo "[*] Enter the target IP for enumeration:"
  read TARGET
  OUTPUT_DIR="enum-results/$TARGET"
  mkdir -p $OUTPUT_DIR

  echo "[*] Starting enumeration for $TARGET..."

  echo "[*] Running Nmap scan..."
  nmap -sC -sV -oN $OUTPUT_DIR/nmap.txt $TARGET

  echo "[*] Running Masscan..."
  masscan -p1-65535 --rate=1000 -oL $OUTPUT_DIR/masscan.txt $TARGET

  echo "[*] Running Enum4Linux..."
  enum4linux $TARGET > $OUTPUT_DIR/enum4linux.txt

  echo "[*] Enumeration completed for $TARGET. Results saved in $OUTPUT_DIR."
}

# Function to perform exploitation automation
exploitation_automation() {
  echo "[*] Enter the target IP for exploitation:"
  read TARGET
  OUTPUT_DIR="exploitation-results/$TARGET"
  mkdir -p $OUTPUT_DIR

  echo "[*] Starting exploitation for $TARGET..."

  echo "[*] Running SQLMap..."
  sqlmap -u "http://$TARGET" --batch --output-dir=$OUTPUT_DIR

  echo "[*] Starting Metasploit..."
  msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; exploit"

  echo "[*] Exploitation completed for $TARGET. Results saved in $OUTPUT_DIR."
}

# Function to perform post-exploitation
post_exploitation() {
  echo "[*] Enter the target IP for post-exploitation:"
  read TARGET
  OUTPUT_DIR="post-exploitation-results/$TARGET"
  mkdir -p $OUTPUT_DIR

  echo "[*] Starting post-exploitation for $TARGET..."

  echo "[*] Running BloodHound..."
  bloodhound-python -c All -u user -p password -d domain.local -ns $TARGET --output $OUTPUT_DIR

  echo "[*] Running Mimikatz..."
  mimikatz -o $OUTPUT_DIR/mimikatz.txt

  echo "[*] Post-exploitation completed for $TARGET. Results saved in $OUTPUT_DIR."
}

# Function to perform post-exploitation and lateral movement
post_exploitation_lateral_movement() {
  echo "[*] Enter the target IP for post-exploitation and lateral movement:"
  read TARGET
  OUTPUT_DIR="post-exploitation-lateral-movement-results/$TARGET"
  mkdir -p $OUTPUT_DIR

  echo "[*] Starting post-exploitation and lateral movement for $TARGET..."

  echo "[*] Running Empire..."
  # Configure Empire to run a PowerShell agentless attack, using HTTP communication
  # For more details: https://github.com/BC-SECURITY/Empire

  echo "[*] Running Mimikatz on the target..."
  # Use Empire to run Mimikatz on the target to gather credentials

  echo "[*] Performing post-exploitation actions..."
  # Examples: data exfiltration, establishing persistence, etc.

  echo "[*] Post-exploitation and lateral movement completed for $TARGET. Results saved in $OUTPUT_DIR."
}

# Function to perform password cracking
password_cracking() {
  echo "[*] Enter the path to the hash file:"
  read HASHFILE
  echo "[*] Enter the path to the wordlist:"
  read WORDLIST
  OUTPUT_DIR="password-cracking-results"
  mkdir -p $OUTPUT_DIR

  echo "[*] Starting password cracking..."

  john --wordlist=$WORDLIST $HASHFILE --pot=$OUTPUT_DIR/john.pot

  echo "[*] Password cracking completed. Results saved in $OUTPUT_DIR."
}

# Function to perform advanced password cracking
advanced_password_cracking() {
  echo "[*] Enter the path to the hash file:"
  read HASHFILE
  echo "[*] Enter the path to the wordlist:"
  read WORDLIST
  echo "[*] Enter the path to the rules file (if applicable):"
  read RULESFILE
  OUTPUT_DIR="advanced-password-cracking-results"
  mkdir -p $OUTPUT_DIR

  echo "[*] Starting advanced password cracking..."

  hashcat -m [hash_type] -a 0 $HASHFILE $WORDLIST -r $RULESFILE --potfile=$OUTPUT_DIR/hashcat.pot --outfile=$OUTPUT_DIR/hashcat.txt

  echo "[*] Advanced password cracking completed. Results saved in $OUTPUT_DIR."
}

# Function to perform web application testing
web_app_testing() {
  echo "[*] Enter the URL for web application testing:"
  read URL
  OUTPUT_DIR="web-app-testing-results"
  mkdir -p $OUTPUT_DIR

  echo "[*] Starting web application testing for $URL..."

  echo "[*] Running Nikto..."
  nikto -h $URL -output $OUTPUT_DIR/nikto.txt

  echo "[*] Running OWASP ZAP..."
  zap-baseline.py -t $URL -r $OUTPUT_DIR/zap.html

  echo "[*] Web application testing completed for $URL. Results saved in $OUTPUT_DIR."
}

# Function to setup network analysis tools
setup_network_analysis_tools() {
  echo "[*] Installing network analysis tools..."
  apt install -y wireshark tcpdump
}

# Function to run vulnerability scanners
run_vulnerability_scanners() {
  echo "[*] Enter the target IP or URL for vulnerability scanning:"
  read TARGET
  OUTPUT_DIR="vulnerability-scanners-results"
  mkdir -p $OUTPUT_DIR

  echo "[*] Running OpenVAS..."
  gvm-start
  gvm-cli tls --gmp-username admin --gmp-password admin socket --xml "<get_reports/>" > $OUTPUT_DIR/openvas.xml

  echo "[*] Running Nessus..."
  /opt/nessus/sbin/nessuscli update --register XXXX-XXXX-XXXX-XXXX --plugins-only
  /opt/nessus/sbin/nessusd -D
  nessus scan list -f json | jq '.[] | select(.status == "completed")' > $OUTPUT_DIR/nessus.json

  echo "[*] Vulnerability scanning completed. Results saved in $OUTPUT_DIR."
}

# Main loop
while true; do
  display_menu

  case $choice in
    1) update_system ;;
    2) install_general_tools ;;
    3) install_recon_tools ;;
    4) install_enum_tools ;;
    5) install_exploitation_tools ;;
    6) install_post_exploitation_tools ;;
    7) install_defense_tools ;;
    8) install_analytics_tools ;;
    9) setup_ufw ;;
    10) setup_fail2ban ;;
    11) setup_splunk ;;
    12) recon_automation ;;
    13) enum_automation ;;
    14) exploitation_automation ;;
    15) post_exploitation ;;
    16) password_cracking ;;
    17) web_app_testing ;;
    18) setup_network_analysis_tools ;;
    19) run_vulnerability_scanners ;;
    20) post_exploitation_lateral_movement ;;
    21) advanced_password_cracking ;;
    0) exit 0 ;;
    *) echo "Invalid option. Please try again." ;;
  esac

  echo "Press Enter to continue..."
  read
done
