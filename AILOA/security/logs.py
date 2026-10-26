import subprocess
from datetime import datetime


def run_command(command):
    """Run a Linux command safely."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0:
            return result.stdout.strip()

        return result.stderr.strip()

    except subprocess.TimeoutExpired:
        return "Command timed out."

    except Exception as e:
        return str(e)


def get_system_logs(lines=30):
    """Get recent system logs."""
    output = run_command(
        [
            "journalctl",
            "-n",
            str(lines),
            "--no-pager"
        ]
    )

    return {
        "status": "SUCCESS",
        "type": "SYSTEM",
        "details": output,
        "timestamp": datetime.now().isoformat()
    }


def get_ssh_logs(lines=30):
    """Get recent SSH logs."""
    output = run_command(
        [
            "journalctl",
            "-u",
            "ssh",
            "-n",
            str(lines),
            "--no-pager"
        ]
    )

    return {
        "status": "SUCCESS",
        "type": "SSH",
        "details": output,
        "timestamp": datetime.now().isoformat()
    }


def get_failed_logins():
    """Check failed login attempts."""
    output = run_command(
        ["journalctl", "--no-pager", "-n", "100"]
    )

    failed_lines = []

    for line in output.splitlines():
        lower_line = line.lower()

        if (
            "failed password" in lower_line
            or "authentication failure" in lower_line
            or "failed login" in lower_line
            or "invalid user" in lower_line
        ):
            failed_lines.append(line)

    return {
        "status": "SUCCESS",
        "count": len(failed_lines),
        "events": failed_lines,
        "timestamp": datetime.now().isoformat()
    }


def analyze_logs():
    """Perform basic security log analysis."""
    system_logs = get_system_logs()
    ssh_logs = get_ssh_logs()
    failed_logins = get_failed_logins()

    if failed_logins["count"] > 0:
        assessment = (
            f"WARNING: {failed_logins['count']} "
            "potential failed login event(s) detected."
        )
    else:
        assessment = "No obvious failed login events detected."

    return {
        "system_logs": system_logs,
        "ssh_logs": ssh_logs,
        "failed_logins": failed_logins,
        "assessment": assessment,
        "timestamp": datetime.now().isoformat()
    }


def display_result(result):
    """Display log analysis results."""
    print()
    print("=" * 60)
    print("                 SYSTEM LOG ANALYSIS")
    print("=" * 60)

    print(f"Assessment: {result['assessment']}")

    print()
    print(
        f"Failed Login Events: "
        f"{result['failed_logins']['count']}"
    )

    if result["failed_logins"]["events"]:
        print()
        print("Potential Failed Login Events:")

        for event in result["failed_logins"]["events"]:
            print(event)

    print()
    print("Recent SSH Logs:")
    print(result["ssh_logs"]["details"])

    print("=" * 60)


def main():
    result = analyze_logs()
    display_result(result)


if __name__ == "__main__":
    main()