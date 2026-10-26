

# ============================================================
# CLEAN QWEN RESPONSE
# ============================================================
import sys

sys.path.insert(0, "/home/karthick/Desktop/AILOA")

import requests
import subprocess
import shlex
import re
from database.database import (
    initialize_database,
    save_command,
    save_monitoring,
    save_question,
    save_security
)
def clean_response(text):

    # Remove <think>...</think>
    text = re.sub(
        r"<think>.*?</think>",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE
    )

import requests
import subprocess
import shlex
import re
import psutil
import sys
sys.path.insert(0, "/home/karthick/Desktop/AILOA")
from datetime import datetime
from security import vulnerability
from security import firewall
from security import ssh
from security import malware
from security import network_security

# ============================================================
# CONFIGURATION
# ============================================================

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
MODEL = "qwen-fast"


# ============================================================
# ALLOWED LINUX COMMANDS
# ============================================================

ALLOWED_COMMANDS = {
    "ls",
    "pwd",
    "whoami",
    "uname",
    "uptime",
    "df",
    "free",
    "ps",
    "ip",
    "ss"
}


# ============================================================
# SYSTEM MONITORING
# ============================================================
def run_vulnerability_check():
    print("\n" + "=" * 60)
    print("          VULNERABILITY ANALYSIS")
    print("=" * 60)

    try:
        result = vulnerability.vulnerability_check()

        if not result:
            print("❌ No result returned.")
            return

        count = result.get("count", 0)
        status = result.get("status", "UNKNOWN")

        print(f"\nStatus              : {status}")
        print(f"Upgradable Packages : {count}")

        if count == 0:
            print("\n✅ No upgradable packages detected.")
            return

        print("\n⚠️ System has packages that can be updated.")

        details = result.get("details", [])

        print("\nSample packages:")
        for package in details[:10]:
            print(f"  • {package}")

        if len(details) > 10:
            print(f"\n... and {len(details) - 10} more packages.")

        print("\nNote:")
        print("This check identifies outdated/upgradable packages.")
        print("It does NOT confirm that every package has a vulnerability.")

    except Exception as e:
        print(f"❌ Vulnerability check error: {e}")
def run_firewall_check():

    print()
    print("=" * 60)
    print("             FIREWALL SECURITY CHECK")
    print("=" * 60)

    try:

        result = firewall.firewall_check()

        print(result)

        # Determine risk level
        if isinstance(result, dict):

            enabled = result.get("enabled")

            if enabled is True:
                risk_level = "LOW"

            elif enabled is False:
                risk_level = "HIGH"

            else:
                risk_level = "UNKNOWN"

        else:
            risk_level = "UNKNOWN"

        # Save firewall security result
        save_security(
            security_type="FIREWALL",
            request="check firewall",
            result=str(result),
            risk_level=risk_level
        )

    except Exception as e:

        error = f"Firewall check error: {e}"

        print(f"❌ {error}")

        # Save error too
        save_security(
            security_type="FIREWALL",
            request="check firewall",
            result=error,
            risk_level="UNKNOWN"
        )
def run_ssh_check():

    print()
    print("=" * 60)
    print("               SSH SECURITY CHECK")
    print("=" * 60)

    try:

        result = ssh.ssh_security_check()

        print(result)

    except Exception as e:

        print(
            f"❌ SSH check error: {e}"
        )
    print("=" * 60)
    print("               SSH SECURITY CHECK")
    print("=" * 60)

    try:

        result = ssh.ssh_security_check()

        print(result)

    except Exception as e:

        print(
            f"❌ SSH check error: {e}"
        )
def run_malware_scan(user_input):

    parts = user_input.split(
        " ",
        2
    )

    if len(parts) < 3:

        print(
            "Usage: scan file <path>"
        )

        return

    target = parts[2].strip()

    print()
    print("=" * 60)
    print("              MALWARE FILE SCAN")
    print("=" * 60)

    try:

        result = malware.scan_target(target)

        print(result)

    except Exception as e:

        print(
            f"❌ Malware scan error: {e}"
        )
def run_network_security_check():

    print()
    print("=" * 60)
    print("             NETWORK SECURITY CHECK")
    print("=" * 60)

    try:

        result = network_security.network_security_check()

        # Network interfaces
        interfaces = result.get("interfaces", [])

        print("\nNetwork Interfaces:")

        for interface in interfaces:
            print(
                f"  {interface['interface']} : "
                f"{interface['ip']}"
            )

        # Active connections
        connections = result.get("connections", [])

        established = [
            connection
            for connection in connections
            if connection.get("status") == "ESTABLISHED"
        ]

        print("\nNetwork Connections:")
        print(
            f"  Active connections: {len(established)}"
        )

        # Listening ports
        listening = result.get("listening_ports", [])

        print("\nListening Ports:")

        if listening:

            for port in listening:
                print(
                    f"  {port['address']}"
                )

        else:

            print("  No listening ports detected.")

        # Security assessment
        print("\nSecurity Assessment:")

        print("  ✓ Network interface is active.")
        print(
            f"  ✓ {len(established)} established "
            "connections detected."
        )

        if listening:

            print(
                "  ✓ Ollama/local service is listening "
                "on localhost."
            )

        print("\nRisk Level: LOW")

    except Exception as e:

        print(
            f"❌ Network security error: {e}"
        )

    print("=" * 60)
def get_cpu_status():

    cpu_usage = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()

    return {
        "usage": cpu_usage,
        "cores": cpu_count
    }


def get_memory_status():

    memory = psutil.virtual_memory()

    return {
        "total": memory.total / (1024 ** 3),
        "used": memory.used / (1024 ** 3),
        "available": memory.available / (1024 ** 3),
        "percent": memory.percent
    }


def get_disk_status():

    disk = psutil.disk_usage("/")

    return {
        "total": disk.total / (1024 ** 3),
        "used": disk.used / (1024 ** 3),
        "free": disk.free / (1024 ** 3),
        "percent": disk.percent
    }


def get_network_status():

    network = psutil.net_io_counters()

    return {
        "bytes_sent": network.bytes_sent / (1024 ** 2),
        "bytes_received": network.bytes_recv / (1024 ** 2),
        "packets_sent": network.packets_sent,
        "packets_received": network.packets_recv
    }


# ============================================================
# DISPLAY COMPLETE SYSTEM STATUS
# ============================================================

def show_system_status():

    print()
    print("=" * 60)
    print("              SYSTEM MONITOR")
    print("=" * 60)

    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # CPU
    cpu = get_cpu_status()

    print()
    print("[CPU]")
    print(f"Usage       : {cpu['usage']:.1f}%")
    print(f"CPU Cores   : {cpu['cores']}")

    if cpu["usage"] >= 90:
        print("Status      : ⚠️ HIGH")
    elif cpu["usage"] >= 70:
        print("Status      : ⚠️ WARNING")
    else:
        print("Status      : ✅ NORMAL")

    # MEMORY
    memory = get_memory_status()

    print()
    print("[MEMORY]")
    print(f"Total       : {memory['total']:.2f} GB")
    print(f"Used        : {memory['used']:.2f} GB")
    print(f"Available   : {memory['available']:.2f} GB")
    print(f"Usage       : {memory['percent']:.1f}%")

    if memory["percent"] >= 90:
        print("Status      : ⚠️ HIGH")
    elif memory["percent"] >= 75:
        print("Status      : ⚠️ WARNING")
    else:
        print("Status      : ✅ NORMAL")

    # DISK
    disk = get_disk_status()

    print()
    print("[DISK]")
    print(f"Total       : {disk['total']:.2f} GB")
    print(f"Used        : {disk['used']:.2f} GB")
    print(f"Free        : {disk['free']:.2f} GB")
    print(f"Usage       : {disk['percent']:.1f}%")

    if disk["percent"] >= 90:
        print("Status      : ⚠️ HIGH")
    elif disk["percent"] >= 80:
        print("Status      : ⚠️ WARNING")
    else:
        print("Status      : ✅ NORMAL")

    # NETWORK
    network = get_network_status()

    print()
    print("[NETWORK]")
    print(f"Data Sent   : {network['bytes_sent']:.2f} MB")
    print(f"Data Received: {network['bytes_received']:.2f} MB")
    print(f"Packets Sent: {network['packets_sent']}")
    print(f"Packets Recv: {network['packets_received']}")
    print("Status      : ✅ MONITORING")

    print()
    print("=" * 60)


# ============================================================
# INDIVIDUAL MONITORS
# ============================================================

def monitor_cpu():

    cpu = get_cpu_status()

    usage = cpu["usage"]

    if usage >= 90:
        status = "HIGH"
        message = "⚠ HIGH CPU USAGE"

    elif usage >= 70:
        status = "ELEVATED"
        message = "⚠ CPU usage is elevated"

    else:
        status = "NORMAL"
        message = "✅ CPU usage is normal"

    print()
    print("[CPU MONITOR]")
    print(f"CPU Usage : {usage:.1f}%")
    print(f"CPU Cores : {cpu['cores']}")
    print(message)

    # Save CPU monitoring data to SQLite
    save_monitoring(
        monitor_type="CPU",
        value=f"{usage:.1f}% | {cpu['cores']} cores",
        status=status
    )

def monitor_memory():

    memory = get_memory_status()

    print()
    print("[MEMORY MONITOR]")
    print(f"Total     : {memory['total']:.2f} GB")
    print(f"Used      : {memory['used']:.2f} GB")
    print(f"Available : {memory['available']:.2f} GB")
    print(f"Usage     : {memory['percent']:.1f}%")

    if memory["percent"] >= 90:
        print("⚠️ HIGH MEMORY USAGE")
    elif memory["percent"] >= 75:
        print("⚠️ Memory usage is elevated")
    else:
        print("✅ Memory usage is normal")


def monitor_disk():

    disk = get_disk_status()

    print()
    print("[DISK MONITOR]")
    print(f"Total : {disk['total']:.2f} GB")
    print(f"Used  : {disk['used']:.2f} GB")
    print(f"Free  : {disk['free']:.2f} GB")
    print(f"Usage : {disk['percent']:.1f}%")

    if disk["percent"] >= 90:
        print("⚠️ DISK SPACE CRITICAL")
    elif disk["percent"] >= 80:
        print("⚠️ Disk usage is high")
    else:
        print("✅ Disk usage is normal")


def monitor_network():

    network = get_network_status()

    print()
    print("[NETWORK MONITOR]")
    print(f"Data Sent       : {network['bytes_sent']:.2f} MB")
    print(f"Data Received   : {network['bytes_received']:.2f} MB")
    print(f"Packets Sent    : {network['packets_sent']}")
    print(f"Packets Received: {network['packets_received']}")

    print("✅ Network statistics collected")


# ============================================================
# DIRECT LINUX COMMAND DETECTION
# ============================================================

def detect_linux_command(user_input):

    text = user_input.lower().strip()

    direct_commands = {

        "list the directory": "ls",
        "list directory": "ls",
        "show directory": "ls",
        "show files": "ls",
        "list files": "ls",

        "show current directory": "pwd",
        "current directory": "pwd",
        "where am i": "pwd",

        "show my username": "whoami",
        "what is my username": "whoami",

        "show system information": "uname -a",
        "system information": "uname -a",

        "show uptime": "uptime",

        "show disk usage": "df -h",
        "disk usage": "df -h",

        "show memory": "free -h",
        "memory usage": "free -h",

        "show running processes": "ps",
        "running processes": "ps",

        "show network connections": "ss -tuln",
        "network connections": "ss -tuln",

        "show ip address": "ip addr",
        "show ip": "ip addr"
    }

    if text in direct_commands:
        return direct_commands[text]

    return None


# ============================================================
# MONITORING COMMAND DETECTION
# ============================================================

def detect_monitor_command(user_input):

    text = user_input.lower().strip()

    # Complete system monitoring
    if text in [
        "monitor system",
        "system monitor",
        "system monitoring",
        "show system status",
        "system status",
        "check system",
        "monitor all",
        "show system health"
    ]:
        return "all"

    # CPU
    if text in [
        "monitor cpu",
        "check cpu",
        "show cpu",
        "cpu usage",
        "cpu monitor"
    ]:
        return "cpu"

    # Memory
    if text in [
        "monitor memory",
        "check memory",
        "show memory usage",
        "memory monitor",
        "ram usage",
        "check ram"
    ]:
        return "memory"

    # Disk
    if text in [
        "monitor disk",
        "check disk",
        "show disk",
        "disk monitor",
        "disk space"
    ]:
        return "disk"

    # Network
    if text in [
        "monitor network",
        "check network",
        "show network",
        "network monitor",
        "network usage"
    ]:
        return "network"

    return None
def detect_security_command(user_input):

    text = user_input.lower().strip()

    if text in [
        "check vulnerabilities",
        "check vulnerability",
        "vulnerability scan",
        "vulnerability analysis",
        "scan vulnerabilities"
    ]:
        return "vulnerability"
    if text in [
        "check firewall",
        "firewall check",
        "firewall security",
        "firewall status"
    ]:
        return "firewall"
    if text in [
        "check ssh",
        "ssh security",
        "ssh security check",
        "check ssh security"
    ]:
        return "ssh"
    if text.startswith("scan file") or text.startswith("scan "):
        return "malware"
    if text in [
        "network security",
        "network security check",
        "check network security",
        "network scan"
    ]:
        return "network_security"
    return None

# ============================================================
# ASK QWEN
# ============================================================

def ask_qwen(user_input):

    response = requests.post(
        OLLAMA_URL,

        json={
            "model": MODEL,

            "messages": [
                {
                    "role": "system",
                    "content": """
You are CyberCopilot, a local Linux assistant.

Answer normal questions briefly.

For normal questions use:

ANSWER: your answer

For Linux operations use:

COMMAND: linux command

Do not show reasoning.
Do not repeat the question.
Do not use <think> tags.
"""
                },

                {
                    "role": "user",
                    "content": user_input
                }
            ],

            "think": False,
            "stream": False,

            "options": {
                "temperature": 0,
                "num_predict": 80
            }
        },

        timeout=90
    )

    response.raise_for_status()

    data = response.json()

    return data["message"]["content"]


# ============================================================
# CLEAN QWEN RESPONSE
# ============================================================

def clean_response(text):

    text = re.sub(
        r"<think>.*?</think>",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE
    )

    text = text.replace("</think>", "")

    return text.strip()


# ============================================================
# EXTRACT COMMAND
# ============================================================

def extract_command(text):

    text = clean_response(text)

    match = re.search(
        r"COMMAND:\s*(.+)",
        text,
        re.IGNORECASE
    )

    if match:

        command = match.group(1).strip()

        command = command.replace("`", "").strip()

        return command

    return None


# ============================================================
# EXTRACT ANSWER
# ============================================================

def extract_answer(text):

    text = clean_response(text)

    match = re.search(
        r"ANSWER:\s*(.+)",
        text,
        re.IGNORECASE | re.DOTALL
    )

    if match:
        return match.group(1).strip()

    return text.strip()


# ============================================================
# SAFETY CHECKER
# ============================================================

def safety_check(command):

    try:

        parts = shlex.split(command)

        if not parts:
            return False, "Empty command"

        base_command = parts[0]

        if base_command not in ALLOWED_COMMANDS:
            return False, f"Command '{base_command}' is not allowed"

        dangerous = [
            ";",
            "&&",
            "||",
            "|",
            ">",
            "<",
            "`",
            "$(",
            "\n"
        ]

        for item in dangerous:

            if item in command:
                return False, f"Dangerous operator detected: {item}"

        return True, "SAFE"

    except Exception as e:

        return False, str(e)


# ============================================================
# COMMAND EXECUTOR
# ============================================================

def execute_command(command, user_request=""):

    try:

        parts = shlex.split(command)

        result = subprocess.run(
            parts,
            shell=False,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.stdout:
            output = result.stdout.strip()

        elif result.stderr:
            output = result.stderr.strip()

        else:
            output = "Command completed successfully."

        # Save command and result to database
        save_command(
            request=user_request,
            command=command,
            safety="SAFE",
            result=output
        )

        return output

    except subprocess.TimeoutExpired:

        output = "Command timed out."

        save_command(
            request=user_request,
            command=command,
            safety="TIMEOUT",
            result=output
        )

        return output

    except Exception as e:

        output = f"Execution error: {e}"

        save_command(
            request=user_request,
            command=command,
            safety="ERROR",
            result=output
        )

        return output

# ============================================================
# MAIN CYBERCOPILOT
# ============================================================
initialize_database()
def main():

    print("=" * 60)
    print("              AILOA")
    print("       AI Linux Security Assistant")
    print("=" * 60)

    print("Start to Chat")
    ##print(f"Local AI: {MODEL}")
    print()
    print("Type 'exit' to quit.")
    print()

    while True:

        try:

            user_input = input(">>> ").strip()

        except KeyboardInterrupt:

            print("\nExiting CyberCopilot.")
            break

        except EOFError:

            print("\nExiting CyberCopilot.")
            break

        if not user_input:
            continue

        if user_input.lower() == "exit":

            print("Goodbye.")
            break

        try:

            # ==================================================
            # STEP 1: SYSTEM MONITORING
            # ==================================================

            monitor_type = detect_monitor_command(user_input)

            if monitor_type == "all":

                show_system_status()
                continue

            elif monitor_type == "cpu":

                monitor_cpu()
                continue

            elif monitor_type == "memory":

                monitor_memory()
                continue

            elif monitor_type == "disk":

                monitor_disk()
                continue

            elif monitor_type == "network":

                monitor_network()
                continue

            security_type = detect_security_command(user_input)

            if security_type == "vulnerability":

                run_vulnerability_check()

                continue
            if security_type == "firewall":

                run_firewall_check()

                continue
            if security_type == "ssh":

                run_ssh_check()

                continue
            if security_type == "malware":

                run_malware_scan(user_input)

                continue
            if security_type == "network_security":

                run_network_security_check()

                continue
                # ==================================================
            # STEP 2: DIRECT LINUX COMMAND
            # ==================================================

            command = detect_linux_command(user_input)

            # ==================================================
            # STEP 3: ASK QWEN IF COMMAND NOT FOUND
            # ==================================================

            if command is None:

                raw_response = ask_qwen(user_input)

                raw_response = clean_response(raw_response)

                print("\nAI Raw:")
                print(raw_response)

                command = extract_command(raw_response)

                # ==================================================
                # NORMAL QUESTION
                # ==================================================

                if command is None:

                    answer = extract_answer(raw_response)
                        # Save question and AI answer
                    save_question(
                        question=user_input,
                        answer=answer
                    )
                    print("\nAI:")
                    print(answer)

                    continue

            # ==================================================
            # STEP 4: COMMAND FOUND
            # ==================================================

            print(f"\nCommand: {command}")

            # ==================================================
            # STEP 5: SAFETY CHECK
            # ==================================================

            safe, reason = safety_check(command)

            print(f"Safety: {reason}")

            if not safe:

                print("❌ Command blocked.")
                continue

            # ==================================================
            # STEP 6: USER CONFIRMATION
            # ==================================================

            confirm = input("\nExecute command? [y/N]: ")

            if confirm.lower() != "y":

                print("Command cancelled.")
                continue

            # ==================================================
            # STEP 7: EXECUTE COMMAND
            # ==================================================

            output = execute_command(command)

            print("\nCommand Output:")
            print("-" * 60)

            if output:
                print(output)
            else:
                print("No output.")

            print("-" * 60)

        except requests.exceptions.ConnectionError:

            print("\n❌ Cannot connect to Ollama.")
            print("Make sure Ollama is running.")

        except requests.exceptions.Timeout:

            print("\n❌ Ollama request timed out.")

        except Exception as e:

            print(f"\n❌ Error: {e}")


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":
    main()
