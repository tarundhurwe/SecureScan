import logging
import json
import subprocess
from ..models import Scan, ScanResult
from . import constants


def run_scan(scan_id, scan_type="all"):
    scan = Scan.objects.get(id=scan_id)
    scan.status = "Running"
    scan.save()

    target_url = scan.url
    results = []
    logging.info(f"Starting the scan for {target_url}")

    try:
        # Nikto Scan (via WSL2)
        if scan_type in ["nikto", "all"]:
            try:
                nikto_command = constants.nikto_command.format(target_url)
                nikto_output = subprocess.check_output(
                    nikto_command, shell=True, text=True
                )

                # Parse Nikto output
                nikto_results = json.loads(nikto_output)
                for item in nikto_results.get("vulnerabilities", []):
                    results.append(
                        {
                            "vulnerability": item.get("msg", "Unknown vulnerability"),
                            "severity": "Medium",
                            "description": item.get(
                                "description", "No description provided"
                            ),
                            "recommendation": "Review server configuration and apply security patches.",
                        }
                    )
            except Exception as e:
                logging.error(f"Failed to run Nikto scan for {target_url}: {e}")

        # Nmap Scan (via WSL2)
        if scan_type in ["nmap", "all"]:
            try:
                nmap_command = constants.nmap_command.format(target_url)
                subprocess.run(nmap_command, shell=True, check=True)

                # Read Nmap XML output from WSL2
                nmap_output = subprocess.check_output(
                    "wsl cat /tmp/nmap_report.xml", shell=True, text=True
                )

                if "<script id=" in nmap_output:
                    results.append(
                        {
                            "vulnerability": "Potential Vulnerability Detected",
                            "severity": "High",
                            "description": "Nmap script detected a potential issue.",
                            "recommendation": "Investigate the service and apply necessary security patches.",
                        }
                    )
            except Exception as e:
                logging.error(f"Failed to run Nmap scan for {target_url}: {e}")

        # Save results to the database
        for vuln in results:
            ScanResult.objects.create(scan=scan, **vuln)

        scan.status = "Completed"
        scan.save()

    except Exception as e:
        logging.error(f"Scan failed for {target_url}: {e}")
        scan.status = "Failed"
        scan.save()
