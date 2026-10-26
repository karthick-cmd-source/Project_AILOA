from datetime import datetime
import vulnerability
import firewall
import malware
import ssh
import network_security

# ============================================================
# VULNERABILITY ANALYSIS
# ============================================================

def analyze_vulnerability(result):

    if result["count"] == 0:
        return {
            "severity": "LOW",
            "alert": False,
            "message": "No packages requiring updates were detected."
        }

    elif result["count"] < 10:
        return {
            "severity": "MEDIUM",
            "alert": True,
            "message": f"{result['count']} packages require attention."
        }

    else:
        return {
            "severity": "HIGH",
            "alert": True,
            "message": f"{result['count']} packages require attention."
        }


# ============================================================
# FIREWALL ANALYSIS
# ============================================================

def analyze_firewall(result):

    if not result["enabled"]:
        return {
            "severity": "MEDIUM",
            "alert": True,
            "message": "Firewall is not detected as active."
        }

    return {
        "severity": "LOW",
        "alert": False,
        "message": f"{result['firewall']} is active."
    }


# ============================================================
# MALWARE ANALYSIS
# ============================================================

def analyze_malware(result):

    if result["status"] == "THREAT":
        return {
            "severity": "HIGH",
            "alert": True,
            "message": result["message"]
        }

    elif result["status"] == "ERROR":
        return {
            "severity": "UNKNOWN",
            "alert": False,
            "message": result["message"]
        }

    return {
        "severity": "LOW",
        "alert": False,
        "message": "No potential threat detected."
    }


# ============================================================
# SSH ANALYSIS
# ============================================================

def analyze_ssh(result):

    service = result.get("service", {})
    port = result.get("port", {})

    service_status = service.get("status", "UNKNOWN")
    port_status = port.get("status", "UNKNOWN")

    if service_status == "RUNNING" and port_status == "OPEN":
        return {
            "severity": "LOW",
            "alert": False,
            "message": "SSH service is running and port 22 is listening."
        }

    elif service_status == "RUNNING":
        return {
            "severity": "LOW",
            "alert": False,
            "message": "SSH service is running."
        }

    elif service_status == "STOPPED":
        return {
            "severity": "LOW",
            "alert": False,
            "message": "SSH service is not running."
        }

    return {
        "severity": "UNKNOWN",
        "alert": False,
        "message": "Unable to determine SSH security status."
    }


# ============================================================
# NETWORK SECURITY ANALYSIS
# ============================================================

def analyze_network(result):

    if not isinstance(result, dict):
        return {
            "severity": "UNKNOWN",
            "alert": False,
            "message": "Invalid network security result."
        }

    status = result.get("status", "UNKNOWN")

    if status == "THREAT":
        return {
            "severity": "HIGH",
            "alert": True,
            "message": result.get(
                "message",
                "Potential network security threat detected."
            )
        }

    elif status == "WARNING":
        return {
            "severity": "MEDIUM",
            "alert": True,
            "message": result.get(
                "message",
                "Potential network security issue detected."
            )
        }

    elif status == "ERROR":
        return {
            "severity": "UNKNOWN",
            "alert": False,
            "message": result.get(
                "message",
                "Network security check failed."
            )
        }

    return {
        "severity": "LOW",
        "alert": False,
        "message": result.get(
            "message",
            "No major network security issue detected."
        )
    }


# ============================================================
# RUN VULNERABILITY CHECK
# ============================================================

def run_vulnerability_check():

    try:
        result = vulnerability.vulnerability_check()

        analysis = analyze_vulnerability(result)

        return {
            "raw_result": result,
            "analysis": analysis
        }

    except Exception as e:

        return {
            "raw_result": {},
            "analysis": {
                "severity": "UNKNOWN",
                "alert": False,
                "message": f"Vulnerability check failed: {str(e)}"
            }
        }


# ============================================================
# RUN FIREWALL CHECK
# ============================================================

def run_firewall_check():

    try:
        result = firewall.firewall_check()

        analysis = analyze_firewall(result)

        return {
            "raw_result": result,
            "analysis": analysis
        }

    except Exception as e:

        return {
            "raw_result": {},
            "analysis": {
                "severity": "UNKNOWN",
                "alert": False,
                "message": f"Firewall check failed: {str(e)}"
            }
        }


# ============================================================
# RUN SSH CHECK
# ============================================================

def run_ssh_check():

    try:
        result = ssh.ssh_security_check()

        analysis = analyze_ssh(result)

        return {
            "raw_result": result,
            "analysis": analysis
        }

    except Exception as e:

        return {
            "raw_result": {},
            "analysis": {
                "severity": "UNKNOWN",
                "alert": False,
                "message": f"SSH check failed: {str(e)}"
            }
        }


# ============================================================
# RUN NETWORK SECURITY CHECK
# ============================================================

def run_network_check():

    try:
        result = network_security.network_security_check()

        analysis = analyze_network(result)

        return {
            "raw_result": result,
            "analysis": analysis
        }

    except Exception as e:

        return {
            "raw_result": {},
            "analysis": {
                "severity": "UNKNOWN",
                "alert": False,
                "message": f"Network security check failed: {str(e)}"
            }
        }


# ============================================================
# RUN MALWARE SCAN
# ============================================================

def run_malware_scan(target):

    try:
        result = malware.scan_target(target)

        analysis = analyze_malware(result)

        return {
            "raw_result": result,
            "analysis": analysis
        }

    except Exception as e:

        return {
            "raw_result": {},
            "analysis": {
                "severity": "UNKNOWN",
                "alert": False,
                "message": f"Malware scan failed: {str(e)}"
            }
        }


# ============================================================
# COMPLETE SECURITY CHECK
# ============================================================

def run_security_check():

    print()
    print("=" * 60)
    print("             AILOA SECURITY ANALYSIS")
    print("=" * 60)

    results = {
        "timestamp": datetime.now().isoformat(),
        "vulnerability": run_vulnerability_check(),
        "firewall": run_firewall_check(),
        "ssh": run_ssh_check(),
        "network": run_network_check()
    }

    return results


# ============================================================
# DISPLAY SECURITY REPORT
# ============================================================

def display_security_report(results):

    print()
    print("=" * 60)
    print("              AILOA SECURITY REPORT")
    print("=" * 60)

    print(f"Time: {results['timestamp']}")

    # --------------------------------------------------------
    # Vulnerability
    # --------------------------------------------------------

    vulnerability_result = results["vulnerability"]["analysis"]

    print()
    print("VULNERABILITY ANALYSIS")
    print("-" * 60)
    print(f"Severity : {vulnerability_result['severity']}")
    print(f"Alert    : {vulnerability_result['alert']}")
    print(f"Message  : {vulnerability_result['message']}")

    # --------------------------------------------------------
    # Firewall
    # --------------------------------------------------------

    firewall_result = results["firewall"]["analysis"]

    print()
    print("FIREWALL ANALYSIS")
    print("-" * 60)
    print(f"Severity : {firewall_result['severity']}")
    print(f"Alert    : {firewall_result['alert']}")
    print(f"Message  : {firewall_result['message']}")

    # --------------------------------------------------------
    # SSH
    # --------------------------------------------------------

    ssh_result = results["ssh"]["analysis"]

    print()
    print("SSH ANALYSIS")
    print("-" * 60)
    print(f"Severity : {ssh_result['severity']}")
    print(f"Alert    : {ssh_result['alert']}")
    print(f"Message  : {ssh_result['message']}")

    # --------------------------------------------------------
    # Network
    # --------------------------------------------------------

    network_result = results["network"]["analysis"]

    print()
    print("NETWORK SECURITY ANALYSIS")
    print("-" * 60)
    print(f"Severity : {network_result['severity']}")
    print(f"Alert    : {network_result['alert']}")
    print(f"Message  : {network_result['message']}")

    print()
    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

def main():

    results = run_security_check()

    display_security_report(results)


if __name__ == "__main__":
    main()