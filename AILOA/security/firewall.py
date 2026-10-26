import subprocess


def run_command(command):

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        return result.stdout.strip(), result.stderr.strip()

    except Exception as e:

        return "", str(e)


def firewall_check():

    # Check UFW
    result = subprocess.run(
        ["which", "ufw"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:

        output, error = run_command(["sudo", "ufw", "status"])

        enabled = "Status: active" in output

        return {
            "firewall": "UFW",
            "enabled": enabled,
            "output": output
        }

    # Check nftables
    result = subprocess.run(
        ["which", "nft"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:

        output, error = run_command(["sudo", "nft", "list", "ruleset"])

        return {
            "firewall": "nftables",
            "enabled": bool(output.strip()),
            "output": output
        }

    # Check iptables
    result = subprocess.run(
        ["which", "iptables"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:

        output, error = run_command(
            ["sudo", "iptables", "-L"]
        )

        return {
            "firewall": "iptables",
            "enabled": bool(output.strip()),
            "output": output
        }

    return {
        "firewall": "None detected",
        "enabled": False,
        "output": ""
    }


if __name__ == "__main__":

    result = firewall_check()

    print("=== Firewall Security Check ===")
    print("Firewall:", result["firewall"])
    print("Enabled:", result["enabled"])

    print("\nConfiguration:")
    print(result["output"])
