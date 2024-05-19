#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root."
  exit 1
fi

LOG_FILE="/var/log/hacking_tool.log"
OUTPUT_DIR="results"

# Function to display ASCII art and menu
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
  echo
  echo "Choose an option from the menu:"
  echo
  echo "               +--------------------------------------+"
  echo "               | 1. Update and upgrade system         |"
  echo "               +--------------------------------------+"
  echo "               | 2. Install Requirements for Pr0x     |"
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
  echo "               | 20. Advanced password cracking       |"
  echo "               +--------------------------------------+"
  echo "               | 21. Deploy listeners                 |"
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

# Function to update and upgrade the system
update_system() {
  log_and_exec "Updating and upgrading the system..." "apt update && apt upgrade -y"
}

# Function to install all requirements for Pr0x
install_requirements_pr0x() {
  log_and_exec "Installing general tools..." "apt install -y git curl wget vim"
  log_and_exec "Installing recon tools..." "apt install -y nmap masscan recon-ng amass sublist3r dnsenum whois whatweb dirsearch theharvester assetfinder"
  log_and_exec "Installing theHarvester from GitHub..." "git clone https://github.com/laramies/theHarvester.git /opt/theHarvester && cd /opt/theHarvester && python3 -m pip install -r requirements/base.txt"
  log_and_exec "Installing enumeration tools..." "apt install -y enum4linux smbclient nbtscan"
  log_and_exec "Installing exploitation tools..." "apt install -y metasploit-framework sqlmap"
  log_and_exec "Installing post-exploitation tools..." "apt install -y bloodhound mimikatz"
  log_and_exec "Installing defense tools..." "apt install -y ufw fail2ban"
  log_and_exec "Installing analytics tools..." "wget -O splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz 'https://download.splunk.com/products/splunk/releases/8.2.2/linux/splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz' && tar -xvf splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz -C /opt && /opt/splunk/bin/splunk start --accept-license && /opt/splunk/bin/splunk enable boot-start"
  log_and_exec "Installing network analysis tools..." "apt install -y wireshark tcpdump"
}

# Function to install recon tools
install_recon_tools() {
  log_and_exec "Installing recon tools..." "apt install -y nmap masscan recon-ng amass sublist3r dnsenum whois whatweb dirsearch theharvester assetfinder"
  log_and_exec "Installing theHarvester from GitHub..." "git clone https://github.com/laramies/theHarvester.git /opt/theHarvester && cd /opt/theHarvester && python3 -m pip install -r requirements/base.txt"
}

# Function to install enumeration tools
install_enum_tools() {
  log_and_exec "Installing enumeration tools..." "apt install -y enum4linux smbclient nbtscan"
}

# Function to install exploitation tools
install_exploitation_tools() {
  log_and_exec "Installing exploitation tools..." "apt install -y metasploit-framework sqlmap"
}

# Function to install post-exploitation tools
install_post_exploitation_tools() {
  log_and_exec "Installing post-exploitation tools..." "apt install -y bloodhound mimikatz"
}

# Function to install defense tools
install_defense_tools() {
  log_and_exec "Installing defense tools..." "apt install -y ufw fail2ban"
}

# Function to install analytics tools
install_analytics_tools() {
  log_and_exec "Installing analytics tools..." "wget -O splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz 'https://download.splunk.com/products/splunk/releases/8.2.2/linux/splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz' && tar -xvf splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz -C /opt && /opt/splunk/bin/splunk start --accept-license && /opt/splunk/bin/splunk enable boot-start"
}

# Function to setup UFW
setup_ufw() {
  log_and_exec "Installing and configuring UFW..." "apt install ufw -y && ufw default deny incoming && ufw default allow outgoing && ufw allow ssh && ufw allow http && ufw allow https && ufw logging on && ufw enable"
}

# Function to setup Fail2Ban
setup_fail2ban() {
  log_and_exec "Installing and configuring Fail2Ban..." "apt install fail2ban -y && systemctl enable fail2ban && systemctl start fail2ban"
}

# Function to setup Splunk
setup_splunk() {
  log_and_exec "Installing Splunk..." "wget -O splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz 'https://download.splunk.com/products/splunk/releases/8.2.2/linux/splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz' && tar -xvf splunk-8.2.2-a7f645ddaf91-Linux-x86_64.tgz -C /opt && /opt/splunk/bin/splunk start --accept-license && /opt/splunk/bin/splunk enable boot-start"
}

# Function to perform recon automation
recon_automation() {
  echo "[*] Enter the target IP or domain for recon:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/recon/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting recon for $TARGET..." "
    nmap -sC -sV -oN $OUTPUT_DIR/nmap.txt $TARGET &&
    masscan -p1-65535 --rate=1000 -oL $OUTPUT_DIR/masscan.txt $TARGET &&
    amass enum -d $TARGET -o $OUTPUT_DIR/amass.txt &&
    sublist3r -d $TARGET -o $OUTPUT_DIR/sublist3r.txt &&
    theHarvester -d $TARGET -b all -f $OUTPUT_DIR/theharvester.txt &&
    assetfinder --subs-only $TARGET > $OUTPUT_DIR/assetfinder.txt
  "

  echo "[*] Recon completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Function to perform enumeration automation
enum_automation() {
  echo "[*] Enter the target IP for enumeration:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/enum/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting enumeration for $TARGET..." "
    nmap -sC -sV -oN $OUTPUT_DIR/nmap.txt $TARGET &&
    masscan -p1-65535 --rate=1000 -oL $OUTPUT_DIR/masscan.txt $TARGET &&
    enum4linux $TARGET > $OUTPUT_DIR/enum4linux.txt
  "

  echo "[*] Enumeration completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Function to perform exploitation automation
exploitation_automation() {
  echo "[*] Enter the target IP for exploitation:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/exploitation/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting exploitation for $TARGET..." "
    sqlmap -u 'http://$TARGET' --batch --output-dir=$OUTPUT_DIR &&
    msfconsole -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; exploit'
  "

  echo "[*] Exploitation completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Function to perform post-exploitation and lateral movement
post_exploitation_lateral_movement() {
  echo "[*] Enter the target IP for post-exploitation and lateral movement:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/post-exploitation-lateral-movement/$TARGET"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting post-exploitation and lateral movement for $TARGET..." "
    echo 'Empire and Mimikatz commands here'
  "

  echo "[*] Post-exploitation and lateral movement completed for $TARGET. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Function to perform advanced password cracking
advanced_password_cracking() {
  echo "[*] Enter the path to the hash file:" | tee -a $LOG_FILE
  read HASHFILE
  echo "[*] Enter the path to the wordlist:" | tee -a $LOG_FILE
  read WORDLIST
  echo "[*] Enter the path to the rules file (if applicable):" | tee -a $LOG_FILE
  read RULESFILE
  OUTPUT_DIR="$OUTPUT_DIR/advanced-password-cracking"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting advanced password cracking..." "
    hashcat -m [hash_type] -a 0 $HASHFILE $WORDLIST -r $RULESFILE --potfile=$OUTPUT_DIR/hashcat.pot --outfile=$OUTPUT_DIR/hashcat.txt
  "

  echo "[*] Advanced password cracking completed. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Function to perform password cracking
password_cracking() {
  echo "[*] Enter the path to the hash file:" | tee -a $LOG_FILE
  read HASHFILE
  echo "[*] Enter the path to the wordlist:" | tee -a $LOG_FILE
  read WORDLIST
  OUTPUT_DIR="$OUTPUT_DIR/password-cracking"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting password cracking..." "john --wordlist=$WORDLIST $HASHFILE --pot=$OUTPUT_DIR/john.pot"

  echo "[*] Password cracking completed. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Function to perform web application testing
web_app_testing() {
  echo "[*] Enter the URL for web application testing:" | tee -a $LOG_FILE
  read URL
  OUTPUT_DIR="$OUTPUT_DIR/web-app-testing"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Starting web application testing for $URL..." "
    nikto -h $URL -output $OUTPUT_DIR/nikto.txt &&
    zap-baseline.py -t $URL -r $OUTPUT_DIR/zap.html
  "

  echo "[*] Web application testing completed for $URL. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Function to setup network analysis tools
setup_network_analysis_tools() {
  log_and_exec "Installing network analysis tools..." "apt install -y wireshark tcpdump"
}

# Function to run vulnerability scanners
run_vulnerability_scanners() {
  echo "[*] Enter the target IP or URL for vulnerability scanning:" | tee -a $LOG_FILE
  read TARGET
  OUTPUT_DIR="$OUTPUT_DIR/vulnerability-scanners"
  mkdir -p $OUTPUT_DIR

  log_and_exec "Running OpenVAS..." "gvm-start && gvm-cli tls --gmp-username admin --gmp-password admin socket --xml '<get_reports/>' > $OUTPUT_DIR/openvas.xml"
  log_and_exec "Running Nessus..." "/opt/nessus/sbin/nessuscli update --register XXXX-XXXX-XXXX-XXXX --plugins-only && /opt/nessus/sbin/nessusd -D && nessus scan list -f json | jq '.[] | select(.status == 'completed')' > $OUTPUT_DIR/nessus.json"

  echo "[*] Vulnerability scanning completed. Results saved in $OUTPUT_DIR." | tee -a $LOG_FILE
}

# Function to deploy listeners
deploy_listeners() {
  echo "[*] Choose a listener to deploy:"
  echo "   1. Metasploit (Reverse TCP)"
  echo "   2. Netcat (Reverse Shell)"
  echo "   3. Custom Listener"
  read listener_choice

  case $listener_choice in
    1)
      echo "[*] Enter the IP to listen on (LHOST):"
      read LHOST
      echo "[*] Enter the port to listen on (LPORT):"
      read LPORT
      log_and_exec "Starting Metasploit listener..." "msfconsole -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST $LHOST; set LPORT $LPORT; exploit'"
      ;;
    2)
      echo "[*] Enter the port to listen on (LPORT):"
      read LPORT
      log_and_exec "Starting Netcat listener..." "nc -lvnp $LPORT"
      ;;
    3)
      echo "[*] Enter the custom listener command:"
      read CUSTOM_LISTENER
      log_and_exec "Starting custom listener..." "$CUSTOM_LISTENER"
      ;;
    *)
      echo "Invalid choice. Please try again."
      ;;
  esac
}

# Function to handle user choice
handle_choice() {
  case $1 in
    1) update_system ;;
    2) install_requirements_pr0x ;;
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
    15) post_exploitation_lateral_movement ;;
    16) password_cracking ;;
    17) web_app_testing ;;
    18) setup_network_analysis_tools ;;
    19) run_vulnerability_scanners ;;
    20) advanced_password_cracking ;;
    21) deploy_listeners ;;
    0) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid option. Please try again." ;;
  esac
}

# Main loop
while true; do
  display_menu
  read choice
  handle_choice $choice
  echo "Press Enter to continue..."
  read
done
