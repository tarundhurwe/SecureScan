nikto_command = "wsl nikto -h {} -o /tmp/nikto_report.json -Format json"
nmap_command = "wsl nmap -Pn -sV {} -oX /tmp/nmap_report.xml"
