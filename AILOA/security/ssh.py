
import subprocess
import sys
from pathlib import Path
from datetime import datetime

# Add the AILOA project root to the Python import path
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.database import save_security


def current_timestamp():
    """Return the current local timestamp."""
    return datetime.now().isoformat()


def check_ssh_service():
    """Check the SSH service state."""

    try:
        result = subprocess.run(
            [
                "systemctl",
                "show",
                "ssh",
                "--property=ActiveState",
                "--value",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        state = result.stdout.strip().lower()

        if result.returncode != 0:
            status = "UNKNOWN"
        elif state == "active":
            status = "RUNNING"
        elif state == "inactive":
            status = "STOPPED"
        elif state == "failed":
            status = "FAILED"
        elif state == "activating":
            status = "STARTING"
        else:
            status = "UNKNOWN"

        return {
            "status": status,
            "service": "ssh",
            "details": state or result.stderr.strip(),
            "timestamp": current_timestamp(),
        }

    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "status": "UNKNOWN",
            "service": "ssh",
            "details": str(error),
            "timestamp": current_timestamp(),
        }


def check_ssh_port():
    """Check whether TCP port 22 has a listening socket."""

    try:
        result = subprocess.run(
            ["ss", "-H", "-ltn"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode != 0:
            return {
                "status": "UNKNOWN",
                "port": 22,
                "details": result.stderr.strip()
                or "Unable to inspect listening TCP ports.",
                "timestamp": current_timestamp(),
            }

        for line in result.stdout.splitlines():
            columns = line.split()

            # Expected columns:
            # State Recv-Q Send-Q LocalAddress:Port PeerAddress:Port
            if len(columns) < 4:
                continue

            local_address = columns[3]

            try:
                local_port = int(local_address.rsplit(":", 1)[1])
            except (ValueError, IndexError):
                continue

            if local_port == 22:
                return {
                    "status": "OPEN",
                    "port": 22,
                    "details": "A listening TCP socket was found on port 22.",
                    "timestamp": current_timestamp(),
                }

        return {
            "status": "CLOSED",
            "port": 22,
            "details": "No listener detected on TCP port 22.",
            "timestamp": current_timestamp(),
        }

    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "status": "UNKNOWN",
            "port": 22,
            "details": str(error),
            "timestamp": current_timestamp(),
        }


def get_ssh_logs():
    """Retrieve recent SSH service logs."""

    try:
        result = subprocess.run(
            [
                "journalctl",
                "-u",
                "ssh",
                "-n",
                "20",
                "--no-pager",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        if result.returncode != 0:
            return {
                "status": "ERROR",
                "details": result.stderr.strip()
                or "Unable to retrieve SSH logs.",
                "timestamp": current_timestamp(),
            }

        return {
            "status": "SUCCESS",
            "details": result.stdout.strip()
            or "No SSH log entries found.",
            "timestamp": current_timestamp(),
        }

    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "status": "ERROR",
            "details": str(error),
            "timestamp": current_timestamp(),
        }


def ssh_security_check():
    """Check SSH service, port, logs, risk, and database logging."""

    service = check_ssh_service()
    port = check_ssh_port()
    logs = get_ssh_logs()

    # Determine the assessment from the observed port state.
    if port["status"] == "OPEN":
        risk_level = "HIGH"
        alert = True
        assessment = (
            "TCP port 22 is listening. Review SSH authentication, "
            "configuration, and network access controls."
        )

    elif port["status"] == "CLOSED" and service["status"] == "STOPPED":
        risk_level = "LOW"
        alert = False
        assessment = (
            "SSH service is stopped and no listener was detected "
            "on TCP port 22."
        )

    elif port["status"] == "CLOSED":
        risk_level = "LOW"
        alert = False
        assessment = (
            "No listener was detected on TCP port 22. "
            "This does not establish that the system is fully secure."
        )

    else:
        risk_level = "UNKNOWN"
        alert = False
        assessment = (
            "Unable to determine SSH port exposure. "
            "Review the check results and errors."
        )

    report = {
        "service": service,
        "port": port,
        "login_activity": logs,
        "risk_level": risk_level,
        "alert": alert,
        "assessment": assessment,
        "timestamp": current_timestamp(),
    }

    # Save the report using the existing AILOA database function.
    try:
        save_security(
            security_type="SSH",
            request="check ssh",
            result=str(report),
            risk_level=risk_level,
        )
        report["database_status"] = "SAVED"

    except Exception as error:
        report["database_status"] = "SAVE FAILED"
        report["database_error"] = str(error)

    return report


def display_result(report):
    """Display the SSH security report."""

    print("\n" + "=" * 60)
    print("                 SSH SECURITY CHECK")
    print("=" * 60)

    print("SSH Service :", report["service"]["status"])
    print("Service Info:", report["service"]["details"])
    print("Port 22     :", report["port"]["status"])
    print("Port Info   :", report["port"]["details"])
    print("Risk Level  :", report["risk_level"])
    print("Alert       :", report["alert"])
    print("Assessment  :", report["assessment"])
    print("Database    :", report["database_status"])

    if report["database_status"] == "SAVE FAILED":
        print("Database Error:", report["database_error"])

    print("\nRecent SSH Logs:")
    print(report["login_activity"]["details"])

    print("=" * 60)


if __name__ == "__main__":
    display_result(ssh_security_check())
