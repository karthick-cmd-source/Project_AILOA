import sys
import os
import requests
import subprocess
import shlex
import re
import psutil
from datetime import datetime


# ============================================================
# AILOA PROJECT PATH
# ============================================================

sys.path.insert(0, "/home/karthick/Desktop/AILOA")


# ============================================================
# DATABASE
# ============================================================

from database.database import (
    initialize_database,
    save_command,
    save_monitoring,
    save_question,
    save_security
)


# ============================================================
# SECURITY MODULES
# ============================================================

from security import vulnerability
from security import firewall
from security import ssh
from security import malware
from security import network_security


# ============================================================
# OLLAMA CONFIGURATION
# ============================================================

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"

# Custom AILOA Ollama model
# Underlying model: Primi4
MODEL = "ailoa"


# ============================================================
# CLEAN LLM RESPONSE
# ============================================================

def clean_response(text):

    if not text:
        return ""

    # Remove thinking blocks
    text = re.sub(
        r"<think>.*?</think>",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE
    )

    text = text.replace("<think>", "")
    text = text.replace("</think>", "")

    # Remove Markdown
    text = text.replace("```bash", "")
    text = text.replace("```shell", "")
    text = text.replace("```sh", "")
    text = text.replace("```text", "")
    text = text.replace("```", "")
    text = text.replace("`", "")

    return text.strip()


# ============================================================
# OLLAMA REQUEST
# ============================================================

def ollama_request(system_prompt, user_input, num_predict=50):

    try:

        response = requests.post(
            OLLAMA_URL,

            json={
                "model": MODEL,

                "messages": [
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": user_input
                    }
                ],

                "stream": False,

                "think": False,

                "options": {
                    "temperature": 0,
                    "num_predict": num_predict,
                    "num_ctx": 1024
                }
            },

            timeout=120
        )

        response.raise_for_status()

        data = response.json()

        if "message" not in data:

            print("\n❌ Invalid Ollama response:")
            print(data)

            return None

        result = data.get(
            "message",
            {}
        ).get(
            "content",
            ""
        )

        result = clean_response(result)

        if not result:

            print(
                "\n❌ Ollama returned an empty response."
            )

            return None

        return result


    except requests.exceptions.ConnectionError:

        print(
            "\n❌ Cannot connect to Ollama."
        )

        print(
            "Make sure Ollama is running."
        )

        return None


    except requests.exceptions.Timeout:

        print(
            "\n❌ Ollama request timed out."
        )

        return None


    except requests.exceptions.RequestException as e:

        print(
            f"\n❌ Ollama API error: {e}"
        )

        return None


    except Exception as e:

        print(
            f"\n❌ Ollama error: {e}"
        )

        return None


# ============================================================
# STEP 1
# LLM REQUEST CLASSIFICATION
# ============================================================

def classify_request(user_input):

    system_prompt = """
You are AILOA, an intent classifier running on Kali Linux.

Classify the user's request.

Return EXACTLY ONE word:

QUESTION

or

COMMAND


==================================================
QUESTION
==================================================

Use QUESTION when the user asks for:

- General knowledge
- Definitions
- Concepts
- Explanations
- Cybersecurity theory
- Linux theory


Examples:

what is an IP address
QUESTION

what is Linux
QUESTION

what is a firewall
QUESTION

how does SSH work
QUESTION

what is DNS
QUESTION

what is a process
QUESTION


==================================================
COMMAND
==================================================

Use COMMAND when the user wants Linux to perform an
operation OR wants information from the actual computer.

Current, live, today's and real-time information from
the computer is always COMMAND.


Examples:

show current date
COMMAND

show current time
COMMAND

what is today's date
COMMAND

what time is it
COMMAND

show my IP address
COMMAND

what is my IP address
COMMAND

show my username
COMMAND

show current directory
COMMAND

list files
COMMAND

list the directory
COMMAND

show memory usage
COMMAND

show disk usage
COMMAND

show running processes
COMMAND

show open ports
COMMAND

show network connections
COMMAND

open Firefox
COMMAND

open Wireshark
COMMAND

open Brave
COMMAND


==================================================
IMPORTANT DISTINCTION
==================================================

General knowledge:

"what is an IP address"
= QUESTION

Computer information:

"what is my IP address"
= COMMAND


General knowledge:

"what is Linux"
= QUESTION

Computer information:

"show my Linux system information"
= COMMAND


Application operation:

"open Firefox"
= COMMAND


==================================================
FINAL RULE
==================================================

If the answer can be obtained from general knowledge:
QUESTION

If Linux must check the actual computer OR perform
an operation on the computer:
COMMAND

Return ONLY:

QUESTION

or

COMMAND
"""

    result = ollama_request(
        system_prompt,
        user_input,
        num_predict=5
    )

    if not result:

        return None

    result = result.upper().strip()

    print(
        f"[LLM DEBUG] Raw classifier response: {result}"
    )

    if result == "QUESTION":

        return "question"

    if result == "COMMAND":

        return "command"

    words = result.split()

    if "QUESTION" in words and "COMMAND" not in words:

        return "question"

    if "COMMAND" in words and "QUESTION" not in words:

        return "command"

    print(
        f"\n❌ Invalid classifier response: {result}"
    )

    return None


# ============================================================
# STEP 2
# NORMAL QUESTION ANSWER
# ============================================================

def generate_answer(user_input):

    system_prompt = """
You are AILOA, an AI Linux Security Assistant.

Answer the user's normal question.

Rules:

- Give a short and clear answer.
- Do not generate Linux commands.
- Do not use COMMAND:
- Do not show reasoning.
- Do not repeat the question.
- Do not use Markdown code blocks.
"""

    result = ollama_request(
        system_prompt,
        user_input,
        num_predict=80
    )

    return result


# ============================================================
# STEP 3
# LINUX COMMAND GENERATION
# ============================================================

def generate_linux_command(user_input):

    print(
        "\n[LLM] Generating Linux command..."
    )

    system_prompt = """
You are AILOA, an AI Linux command generator running
on Kali Linux.

Convert the user's request into EXACTLY ONE valid
Linux command.

==================================================
CRITICAL SECURITY RULE
==================================================

You MUST understand the user's actual request.

NEVER replace a dangerous request with an unrelated
safe command.

If the user requests a dangerous operation, preserve
the requested operation so the independent safety
checker can detect and block it.

Example:

User:
rm -rf ~/Desktop/*

Correct output:
rm -rf ~/Desktop/*

WRONG:
df -h

WRONG:
ls

WRONG:
pwd


==================================================
COMMAND RULES
==================================================

1. Return ONLY ONE Linux command.

2. Do NOT explain the command.

3. Do NOT use Markdown.

4. Do NOT generate multiple commands.

5. Do NOT use shell operators:

;
&&
||
|
>
<
>>
`
$()

6. Do NOT use shell pipelines.

7. Use standard Linux commands available on Kali Linux.

8. NEVER invent Linux command options.

9. Use simple and valid Linux syntax.

10. Do NOT add unnecessary paths or arguments.

11. Do NOT use sudo unless genuinely required.

12. If the user asks to open an application, return
    its normal Linux executable.

13. If the user asks for system information, return
    the appropriate Linux command.

14. Preserve the exact meaning of the user's request.

15. Do NOT convert one request into another request.


==================================================
VALID COMMAND EXAMPLES
==================================================

User: list the directory
Output: ls

User: list files
Output: ls

User: list files in detail
Output: ls -l

User: show hidden files
Output: ls -la

User: show current directory
Output: pwd

User: show current date
Output: date

User: show current time
Output: date

User: show my IP address
Output: ip addr

User: show memory usage
Output: free -h

User: show disk usage
Output: df -h

User: show running processes
Output: ps aux

User: show network connections
Output: ss -tuln

User: open Firefox
Output: firefox

User: open Wireshark
Output: wireshark

User: open Brave
Output: brave-browser

User: open VS Code
Output: code

User: scan localhost using nmap
Output: nmap localhost

User: delete everything from desktop
Output: rm -rf ~/Desktop/*

User: shutdown the computer
Output: shutdown now


==================================================
FINAL RULE
==================================================

Return ONLY ONE valid Linux command.
"""

    result = ollama_request(
        system_prompt,
        user_input,
        num_predict=100
    )

    if not result:

        print(
            "[LLM ERROR] No command generated."
        )

        return None


    command = clean_response(
        result
    ).strip()


    # ========================================================
    # REMOVE MARKDOWN
    # ========================================================

    command = command.replace(
        "```bash",
        ""
    )

    command = command.replace(
        "```shell",
        ""
    )

    command = command.replace(
        "```sh",
        ""
    )

    command = command.replace(
        "```",
        ""
    )

    command = command.strip()


    # ========================================================
    # ONLY FIRST LINE
    # ========================================================

    command = command.splitlines()[0].strip()


    # ========================================================
    # REMOVE ACCIDENTAL PREFIX
    # ========================================================

    prefixes = [
        "Command:",
        "command:",
        "COMMAND:",
        "Output:",
        "output:",
        "OUTPUT:"
    ]

    for prefix in prefixes:

        if command.startswith(prefix):

            command = command[
                len(prefix):
            ].strip()


    # ========================================================
    # EMPTY COMMAND
    # ========================================================

    if not command:

        print(
            "[LLM ERROR] Empty command generated."
        )

        return None


    print(
        f"[LLM] Generated: {command}"
    )

    return command


# ============================================================
# SAFETY CHECKER
# ============================================================

def safety_check(command, user_request=""):

    try:

        # ====================================================
        # CHECK ORIGINAL USER REQUEST FIRST
        # ====================================================

        original_text = (
            user_request
            .lower()
            .strip()
        )


        dangerous_request_patterns = [

            r"\brm\b",

            r"\brm\s+-",

            r"\brm\s+-rf\b",

            r"\brm\s+-fr\b",

            r"\bremove\s+all\b",

            r"\bdelete\s+all\b",

            r"\bdelete\s+everything\b",

            r"\bdelete\s+files\b",

            r"\bdelete\s+folder\b",

            r"\bformat\s+disk\b",

            r"\bformat\s+drive\b",

            r"\bshutdown\b",

            r"\breboot\b",

            r"\bpoweroff\b",

            r"\bkill\s+all\b",

            r"\bkill\s+process\b",

            r"\bterminate\s+all\b",

            r"\bmkfs\b",

            r"\bfdisk\b",

            r"\bparted\b",

            r"\bdd\b",

            r"\bchmod\b",

            r"\bchown\b"
        ]


        for pattern in dangerous_request_patterns:

            if re.search(
                pattern,
                original_text
            ):

                return (
                    False,
                    "BLOCKED: Dangerous request detected."
                )


        # ====================================================
        # PARSE COMMAND
        # ====================================================

        parts = shlex.split(
            command
        )

        if not parts:

            return (
                False,
                "BLOCKED: Empty command."
            )


        # ====================================================
        # DANGEROUS SHELL OPERATORS
        # ====================================================

        dangerous_operators = [
            ";",
            "&&",
            "||",
            "|",
            ">",
            "<",
            ">>",
            "`",
            "$(",
            "\n"
        ]


        for item in dangerous_operators:

            if item in command:

                return (
                    False,
                    f"BLOCKED: Dangerous operator detected: {item}"
                )


        # ====================================================
        # BLOCKED COMMANDS
        # ====================================================

        blocked_commands = {
            "rm",
            "chmod",
            "chown",
            "shutdown",
            "reboot",
            "poweroff",
            "halt",
            "kill",
            "pkill",
            "dd",
            "mkfs",
            "fdisk",
            "parted"
        }


        # ====================================================
        # SUDO
        # ====================================================

        if parts[0] == "sudo":

            if len(parts) < 2:

                return (
                    False,
                    "BLOCKED: Incomplete sudo command."
                )


            actual_command = parts[1]


            if actual_command in blocked_commands:

                return (
                    False,
                    f"BLOCKED: Dangerous sudo command "
                    f"'{actual_command}'."
                )


            # =================================================
            # APT
            # =================================================

            if actual_command in [
                "apt",
                "apt-get"
            ]:

                if len(parts) < 3:

                    return (
                        False,
                        "BLOCKED: Missing apt operation."
                    )


                operation = parts[2]


                if operation in [
                    "install",
                    "update",
                    "upgrade"
                ]:

                    return (
                        True,
                        "WARNING: Administrator permission "
                        "required. User confirmation required."
                    )


                return (
                    False,
                    f"BLOCKED: apt operation "
                    f"'{operation}' is not allowed."
                )


            return (
                False,
                f"BLOCKED: sudo '{actual_command}' "
                f"is not permitted."
            )


        # ====================================================
        # NORMAL COMMAND
        # ====================================================

        base_command = parts[0]


        if base_command in blocked_commands:

            return (
                False,
                f"BLOCKED: Dangerous command "
                f"'{base_command}'."
            )


        # ====================================================
        # NORMAL COMMAND
        # ====================================================

        return (
            True,
            "SAFE: User confirmation required"
        )


    except ValueError as e:

        return (
            False,
            f"BLOCKED: Invalid command syntax: {e}"
        )


    except Exception as e:

        return (
            False,
            f"BLOCKED: {e}"
        )


# ============================================================
# COMMAND EXECUTOR
# ============================================================

def execute_command(command, user_request=""):

    try:

        # ====================================================
        # SPLIT COMMAND
        # ====================================================

        parts = shlex.split(
            command
        )

        if not parts:

            return "Empty command."


        # ====================================================
        # BASE EXECUTABLE
        # ====================================================

        executable = parts[0]


        # ====================================================
        # CHECK COMMAND EXISTS
        # ====================================================

        executable_path = subprocess.run(
            ["which", executable],
            capture_output=True,
            text=True,
            timeout=3
        )


        if executable_path.returncode != 0:

            output = (
                f"Command not found: {executable}"
            )

            save_command(
                request=user_request,
                command=command,
                safety="ERROR",
                result=output
            )

            return output


        # ====================================================
        # GUI APPLICATIONS
        # ====================================================

        gui_applications = {
            "firefox",
            "firefox-esr",
            "wireshark",
            "brave",
            "brave-browser",
            "code",
            "code-insiders",
            "gedit",
            "nautilus",
            "thunar"
        }


        # ====================================================
        # GUI EXECUTION
        # ====================================================

        if executable in gui_applications:

            process = subprocess.Popen(
                parts,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )


            output = (
                f"{executable} started successfully "
                f"(PID: {process.pid})."
            )


            save_command(
                request=user_request,
                command=command,
                safety="SAFE",
                result=output
            )


            return output


        # ====================================================
        # NORMAL TERMINAL COMMAND
        # ====================================================

        result = subprocess.run(
            parts,
            shell=False,
            capture_output=True,
            text=True,
            timeout=60
        )


        # ====================================================
        # OUTPUT
        # ====================================================

        if result.stdout:

            output = result.stdout.strip()

        elif result.stderr:

            output = result.stderr.strip()

        else:

            output = (
                "Command completed successfully."
            )


        # ====================================================
        # SAVE RESULT
        # ====================================================

        save_command(
            request=user_request,
            command=command,
            safety="SAFE",
            result=output
        )


        return output


    except subprocess.TimeoutExpired:

        output = (
            "Command timed out."
        )


        save_command(
            request=user_request,
            command=command,
            safety="TIMEOUT",
            result=output
        )


        return output


    except Exception as e:

        output = (
            f"Execution error: {e}"
        )


        save_command(
            request=user_request,
            command=command,
            safety="ERROR",
            result=output
        )


        return output


# ============================================================
# VULNERABILITY ANALYSIS
# ============================================================

def run_vulnerability_check():

    print()
    print("=" * 60)
    print("          VULNERABILITY ANALYSIS")
    print("=" * 60)


    try:

        result = vulnerability.vulnerability_check()


        if not result:

            print(
                "❌ No result returned."
            )

            return


        count = result.get(
            "count",
            0
        )


        status = result.get(
            "status",
            "UNKNOWN"
        )


        print(
            f"\nStatus              : {status}"
        )


        print(
            f"Upgradable Packages : {count}"
        )


        if count == 0:

            print(
                "\n✅ No upgradable packages detected."
            )


            save_security(
                security_type="VULNERABILITY",
                request="check vulnerabilities",
                result=str(result),
                risk_level="LOW"
            )


            return


        print(
            "\n⚠️ System has packages that can be updated."
        )


        details = result.get(
            "details",
            []
        )


        print(
            "\nSample packages:"
        )


        for package in details[:10]:

            print(
                f"  • {package}"
            )


        if len(details) > 10:

            print(
                f"\n... and "
                f"{len(details) - 10} more packages."
            )


        print("\nNote:")


        print(
            "This check identifies outdated/upgradable packages."
        )


        print(
            "It does NOT confirm that every package has a vulnerability."
        )


        if count < 10:

            risk_level = "MEDIUM"

        else:

            risk_level = "HIGH"


        save_security(
            security_type="VULNERABILITY",
            request="check vulnerabilities",
            result=str(result),
            risk_level=risk_level
        )


    except Exception as e:

        error = (
            f"Vulnerability check error: {e}"
        )


        print(
            f"❌ {error}"
        )


        save_security(
            security_type="VULNERABILITY",
            request="check vulnerabilities",
            result=error,
            risk_level="UNKNOWN"
        )


# ============================================================
# FIREWALL SECURITY CHECK
# ============================================================

def run_firewall_check():

    print()
    print("=" * 60)
    print("             FIREWALL SECURITY CHECK")
    print("=" * 60)


    try:

        result = firewall.firewall_check()

        print(result)


        if isinstance(result, dict):

            enabled = result.get(
                "enabled"
            )


            if enabled is True:

                risk_level = "LOW"

            elif enabled is False:

                risk_level = "HIGH"

            else:

                risk_level = "UNKNOWN"


        else:

            risk_level = "UNKNOWN"


        save_security(
            security_type="FIREWALL",
            request="check firewall",
            result=str(result),
            risk_level=risk_level
        )


    except Exception as e:

        error = (
            f"Firewall check error: {e}"
        )


        print(
            f"❌ {error}"
        )


        save_security(
            security_type="FIREWALL",
            request="check firewall",
            result=error,
            risk_level="UNKNOWN"
        )


    print(
        "=" * 60
    )


# ============================================================
# SSH SECURITY CHECK
# ============================================================

def run_ssh_check():

    print()
    print("=" * 60)
    print("               SSH SECURITY CHECK")
    print("=" * 60)


    try:

        result = ssh.ssh_security_check()

        print(result)


        save_security(
            security_type="SSH",
            request="check ssh",
            result=str(result),
            risk_level="ANALYZED"
        )


    except Exception as e:

        error = (
            f"SSH check error: {e}"
        )


        print(
            f"❌ {error}"
        )


        save_security(
            security_type="SSH",
            request="check ssh",
            result=error,
            risk_level="UNKNOWN"
        )


    print(
        "=" * 60
    )


# ============================================================
# MALWARE FILE SCAN
# ============================================================

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

        result = malware.scan_target(
            target
        )


        print(result)


        if isinstance(result, dict):

            status = str(
                result.get(
                    "status",
                    ""
                )
            ).upper()


            if status == "THREAT":

                risk_level = "HIGH"

            elif status == "CLEAN":

                risk_level = "LOW"

            else:

                risk_level = "UNKNOWN"


        else:

            risk_level = "UNKNOWN"


        save_security(
            security_type="MALWARE",
            request=user_input,
            result=str(result),
            risk_level=risk_level
        )


    except Exception as e:

        error = (
            f"Malware scan error: {e}"
        )


        print(
            f"❌ {error}"
        )


        save_security(
            security_type="MALWARE",
            request=user_input,
            result=error,
            risk_level="UNKNOWN"
        )


    print(
        "=" * 60
    )


# ============================================================
# NETWORK SECURITY CHECK
# ============================================================

def run_network_security_check():

    print()
    print("=" * 60)
    print("             NETWORK SECURITY CHECK")
    print("=" * 60)


    try:

        result = (
            network_security.network_security_check()
        )


        # ====================================================
        # NETWORK INTERFACES
        # ====================================================

        interfaces = result.get(
            "interfaces",
            []
        )


        print(
            "\nNetwork Interfaces:"
        )


        for interface in interfaces:

            print(
                f"  {interface['interface']} : "
                f"{interface['ip']}"
            )


        # ====================================================
        # CONNECTIONS
        # ====================================================

        connections = result.get(
            "connections",
            []
        )


        established = [
            connection
            for connection in connections
            if connection.get("status") == "ESTABLISHED"
        ]


        print(
            "\nNetwork Connections:"
        )


        print(
            f"  Active connections: "
            f"{len(established)}"
        )


        # ====================================================
        # LISTENING PORTS
        # ====================================================

        listening = result.get(
            "listening_ports",
            []
        )


        print(
            "\nListening Ports:"
        )


        if listening:

            for port in listening:

                print(
                    f"  {port['address']}"
                )

        else:

            print(
                "  No listening ports detected."
            )


        # ====================================================
        # ASSESSMENT
        # ====================================================

        print(
            "\nSecurity Assessment:"
        )


        print(
            "  ✓ Network interface information collected."
        )


        print(
            f"  ✓ {len(established)} established "
            "connections detected."
        )


        if listening:

            print(
                f"  ✓ {len(listening)} listening "
                "port(s) detected."
            )


        print(
            "\nRisk Level: LOW"
        )


        save_security(
            security_type="NETWORK",
            request="network security check",
            result=str(result),
            risk_level="LOW"
        )


    except Exception as e:

        error = (
            f"Network security error: {e}"
        )


        print(
            f"❌ {error}"
        )


        save_security(
            security_type="NETWORK",
            request="network security check",
            result=error,
            risk_level="UNKNOWN"
        )


    print(
        "=" * 60
    )


# ============================================================
# CPU STATUS
# ============================================================

def get_cpu_status():

    cpu_usage = psutil.cpu_percent(
        interval=1
    )

    cpu_count = psutil.cpu_count()


    return {
        "usage": cpu_usage,
        "cores": cpu_count
    }


# ============================================================
# MEMORY STATUS
# ============================================================

def get_memory_status():

    memory = psutil.virtual_memory()


    return {
        "total": memory.total / (1024 ** 3),
        "used": memory.used / (1024 ** 3),
        "available": memory.available / (1024 ** 3),
        "percent": memory.percent
    }


# ============================================================
# DISK STATUS
# ============================================================

def get_disk_status():

    disk = psutil.disk_usage("/")


    return {
        "total": disk.total / (1024 ** 3),
        "used": disk.used / (1024 ** 3),
        "free": disk.free / (1024 ** 3),
        "percent": disk.percent
    }


# ============================================================
# NETWORK STATUS
# ============================================================

def get_network_status():

    network = psutil.net_io_counters()


    return {
        "bytes_sent": (
            network.bytes_sent /
            (1024 ** 2)
        ),

        "bytes_received": (
            network.bytes_recv /
            (1024 ** 2)
        ),

        "packets_sent": (
            network.packets_sent
        ),

        "packets_received": (
            network.packets_recv
        )
    }


# ============================================================
# COMPLETE SYSTEM STATUS
# ============================================================

def show_system_status():

    print()
    print("=" * 60)
    print("              SYSTEM MONITOR")
    print("=" * 60)


    print(
        "Time: "
        + datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )


    # ========================================================
    # CPU
    # ========================================================

    cpu = get_cpu_status()


    print()
    print("[CPU]")


    print(
        f"Usage       : "
        f"{cpu['usage']:.1f}%"
    )


    print(
        f"CPU Cores   : "
        f"{cpu['cores']}"
    )


    if cpu["usage"] >= 90:

        cpu_status = "HIGH"

        print(
            "Status      : ⚠️ HIGH"
        )

    elif cpu["usage"] >= 70:

        cpu_status = "WARNING"

        print(
            "Status      : ⚠️ WARNING"
        )

    else:

        cpu_status = "NORMAL"

        print(
            "Status      : ✅ NORMAL"
        )


    save_monitoring(
        monitor_type="CPU",
        value=f"{cpu['usage']:.1f}%",
        status=cpu_status
    )


    # ========================================================
    # MEMORY
    # ========================================================

    memory = get_memory_status()


    print()
    print("[MEMORY]")


    print(
        f"Total       : "
        f"{memory['total']:.2f} GB"
    )


    print(
        f"Used        : "
        f"{memory['used']:.2f} GB"
    )


    print(
        f"Available   : "
        f"{memory['available']:.2f} GB"
    )


    print(
        f"Usage       : "
        f"{memory['percent']:.1f}%"
    )


    if memory["percent"] >= 90:

        memory_status = "HIGH"

        print(
            "Status      : ⚠️ HIGH"
        )

    elif memory["percent"] >= 75:

        memory_status = "WARNING"

        print(
            "Status      : ⚠️ WARNING"
        )

    else:

        memory_status = "NORMAL"

        print(
            "Status      : ✅ NORMAL"
        )


    save_monitoring(
        monitor_type="MEMORY",
        value=f"{memory['percent']:.1f}%",
        status=memory_status
    )


    # ========================================================
    # DISK
    # ========================================================

    disk = get_disk_status()


    print()
    print("[DISK]")


    print(
        f"Total       : "
        f"{disk['total']:.2f} GB"
    )


    print(
        f"Used        : "
        f"{disk['used']:.2f} GB"
    )


    print(
        f"Free        : "
        f"{disk['free']:.2f} GB"
    )


    print(
        f"Usage       : "
        f"{disk['percent']:.1f}%"
    )


    if disk["percent"] >= 90:

        disk_status = "HIGH"

        print(
            "Status      : ⚠️ HIGH"
        )

    elif disk["percent"] >= 80:

        disk_status = "WARNING"

        print(
            "Status      : ⚠️ WARNING"
        )

    else:

        disk_status = "NORMAL"

        print(
            "Status      : ✅ NORMAL"
        )


    save_monitoring(
        monitor_type="DISK",
        value=f"{disk['percent']:.1f}%",
        status=disk_status
    )


    # ========================================================
    # NETWORK
    # ========================================================

    network = get_network_status()


    print()
    print("[NETWORK]")


    print(
        f"Data Sent    : "
        f"{network['bytes_sent']:.2f} MB"
    )


    print(
        f"Data Received: "
        f"{network['bytes_received']:.2f} MB"
    )


    print(
        f"Packets Sent : "
        f"{network['packets_sent']}"
    )


    print(
        f"Packets Recv : "
        f"{network['packets_received']}"
    )


    print(
        "Status       : ✅ MONITORING"
    )


    save_monitoring(
        monitor_type="NETWORK",
        value=(
            f"Sent={network['bytes_sent']:.2f} MB | "
            f"Received={network['bytes_received']:.2f} MB"
        ),
        status="NORMAL"
    )


    print()
    print("=" * 60)


# ============================================================
# INDIVIDUAL CPU MONITOR
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


    print(
        f"CPU Usage : "
        f"{usage:.1f}%"
    )


    print(
        f"CPU Cores : "
        f"{cpu['cores']}"
    )


    print(message)


    save_monitoring(
        monitor_type="CPU",
        value=(
            f"{usage:.1f}% | "
            f"{cpu['cores']} cores"
        ),
        status=status
    )


# ============================================================
# INDIVIDUAL MEMORY MONITOR
# ============================================================

def monitor_memory():

    memory = get_memory_status()

    usage = memory["percent"]


    if usage >= 90:

        status = "HIGH"

        message = "⚠ HIGH MEMORY USAGE"

    elif usage >= 75:

        status = "ELEVATED"

        message = "⚠ Memory usage is elevated"

    else:

        status = "NORMAL"

        message = "✅ Memory usage is normal"


    print()
    print("[MEMORY MONITOR]")


    print(
        f"Total     : "
        f"{memory['total']:.2f} GB"
    )


    print(
        f"Used      : "
        f"{memory['used']:.2f} GB"
    )


    print(
        f"Available : "
        f"{memory['available']:.2f} GB"
    )


    print(
        f"Usage     : "
        f"{usage:.1f}%"
    )


    print(message)


    save_monitoring(
        monitor_type="MEMORY",
        value=(
            f"{usage:.1f}% | "
            f"Used={memory['used']:.2f} GB"
        ),
        status=status
    )


# ============================================================
# INDIVIDUAL DISK MONITOR
# ============================================================

def monitor_disk():

    disk = get_disk_status()

    usage = disk["percent"]


    if usage >= 90:

        status = "HIGH"

        message = "⚠ DISK SPACE CRITICAL"

    elif usage >= 80:

        status = "ELEVATED"

        message = "⚠ Disk usage is high"

    else:

        status = "NORMAL"

        message = "✅ Disk usage is normal"


    print()
    print("[DISK MONITOR]")


    print(
        f"Total : "
        f"{disk['total']:.2f} GB"
    )


    print(
        f"Used  : "
        f"{disk['used']:.2f} GB"
    )


    print(
        f"Free  : "
        f"{disk['free']:.2f} GB"
    )


    print(
        f"Usage : "
        f"{usage:.1f}%"
    )


    print(message)


    save_monitoring(
        monitor_type="DISK",
        value=(
            f"{usage:.1f}% | "
            f"Free={disk['free']:.2f} GB"
        ),
        status=status
    )


# ============================================================
# INDIVIDUAL NETWORK MONITOR
# ============================================================

def monitor_network():

    network = get_network_status()


    print()
    print("[NETWORK MONITOR]")


    print(
        f"Data Sent       : "
        f"{network['bytes_sent']:.2f} MB"
    )


    print(
        f"Data Received   : "
        f"{network['bytes_received']:.2f} MB"
    )


    print(
        f"Packets Sent    : "
        f"{network['packets_sent']}"
    )


    print(
        f"Packets Received: "
        f"{network['packets_received']}"
    )


    print(
        "✅ Network statistics collected"
    )


    save_monitoring(
        monitor_type="NETWORK",
        value=(
            f"Sent={network['bytes_sent']:.2f} MB | "
            f"Received={network['bytes_received']:.2f} MB | "
            f"Packets Sent={network['packets_sent']} | "
            f"Packets Received={network['packets_received']}"
        ),
        status="NORMAL"
    )


# ============================================================
# MONITORING COMMAND DETECTION
# ============================================================

def detect_monitor_command(user_input):

    text = user_input.lower().strip()


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


    if text in [
        "monitor cpu",
        "check cpu",
        "show cpu",
        "cpu usage",
        "cpu monitor"
    ]:

        return "cpu"


    if text in [
        "monitor memory",
        "check memory",
        "show memory usage",
        "memory monitor",
        "ram usage",
        "check ram"
    ]:

        return "memory"


    if text in [
        "monitor disk",
        "check disk",
        "show disk",
        "disk monitor",
        "disk space"
    ]:

        return "disk"


    if text in [
        "monitor network",
        "check network",
        "show network",
        "network monitor",
        "network usage"
    ]:

        return "network"


    return None


# ============================================================
# SECURITY COMMAND DETECTION
# ============================================================

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


    if (
        text.startswith("scan file")
        or text.startswith("scan ")
    ):

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
# MAIN AILOA ASSISTANT
# ============================================================

def main():

    # ========================================================
    # INITIALIZE DATABASE
    # ========================================================

    initialize_database()


    # ========================================================
    # HEADER
    # ========================================================

    print("=" * 60)

    print(
        "              AILOA"
    )

    print(
        "       AI Linux Security Assistant"
    )

    print("=" * 60)

    print(
        "Local AI: "
        + MODEL
    )

    print()
    print("Start Chating")
    print(
        "Type 'exit' to quit."
    )

    print()


    # ========================================================
    # MAIN LOOP
    # ========================================================

    while True:

        try:

            user_input = input(
                ">>> "
            ).strip()


        except KeyboardInterrupt:

            print(
                "\nExiting AILOA."
            )

            break


        except EOFError:

            print(
                "\nExiting AILOA."
            )

            break


        # ====================================================
        # EMPTY INPUT
        # ====================================================

        if not user_input:

            continue


        # ====================================================
        # EXIT
        # ====================================================

        if user_input.lower() == "exit":

            print(
                "Goodbye."
            )

            break


        try:

            # =================================================
            # STEP 1
            # SYSTEM MONITORING
            # =================================================

            monitor_type = detect_monitor_command(
                user_input
            )


            if monitor_type == "all":

                show_system_status()

                continue


            if monitor_type == "cpu":

                monitor_cpu()

                continue


            if monitor_type == "memory":

                monitor_memory()

                continue


            if monitor_type == "disk":

                monitor_disk()

                continue


            if monitor_type == "network":

                monitor_network()

                continue


            # =================================================
            # STEP 2
            # SECURITY ANALYSIS
            # =================================================

            security_type = detect_security_command(
                user_input
            )


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

                run_malware_scan(
                    user_input
                )

                continue


            if security_type == "network_security":

                run_network_security_check()

                continue


            # =================================================
            # STEP 3
            # LLM CLASSIFICATION
            # =================================================

            print(
                "\n[LLM] Classifying request..."
            )


            request_type = classify_request(
                user_input
            )


            if request_type == "question":

                print(
                    "[LLM] Request type: QUESTION"
                )


                answer = generate_answer(
                    user_input
                )


                if answer:

                    save_question(
                        question=user_input,
                        answer=answer
                    )


                    print()
                    print("AI:")
                    print(answer)


                else:

                    print(
                        "\n❌ Unable to generate answer."
                    )


                continue


            # =================================================
            # STEP 4
            # COMMAND
            # =================================================

            if request_type == "command":

                print(
                    "[LLM] Request type: COMMAND"
                )


                command = generate_linux_command(
                    user_input
                )


                if not command:

                    print(
                        "\n❌ Unable to generate Linux command."
                    )

                    continue


            else:

                print(
                    "\n❌ Unable to classify request."
                )

                continue


            # =================================================
            # STEP 5
            # DISPLAY COMMAND
            # =================================================

            print()

            print(
                f"Command: {command}"
            )


            # =================================================
            # STEP 6
            # SAFETY CHECK
            # =================================================

            safe, reason = safety_check(
                command,
                user_input
            )


            print(
                f"Safety: {reason}"
            )


            # =================================================
            # BLOCK UNSAFE COMMAND
            # =================================================

            if not safe:

                print(
                    "❌ Command blocked."
                )


                save_command(
                    request=user_input,
                    command=command,
                    safety="BLOCKED",
                    result=reason
                )


                continue


            # =================================================
            # STEP 7
            # USER CONFIRMATION
            # =================================================

            confirm = input(
                "\nExecute command? [y/N]: "
            )


            # =================================================
            # CANCEL
            # =================================================

            if confirm.lower() != "y":

                print(
                    "Command cancelled."
                )


                save_command(
                    request=user_input,
                    command=command,
                    safety="CANCELLED",
                    result="User cancelled execution"
                )


                continue


            # =================================================
            # STEP 8
            # EXECUTE
            # =================================================

            output = execute_command(
                command,
                user_input
            )


            # =================================================
            # STEP 9
            # OUTPUT
            # =================================================

            print()

            print(
                "Command Output:"
            )

            print(
                "-" * 60
            )


            if output:

                print(output)

            else:

                print(
                    "No output."
                )


            print(
                "-" * 60
            )


        # =====================================================
        # OLLAMA CONNECTION ERROR
        # =====================================================

        except requests.exceptions.ConnectionError:

            print()

            print(
                "❌ Cannot connect to Ollama."
            )

            print(
                "Make sure Ollama is running."
            )


        # =====================================================
        # OLLAMA TIMEOUT
        # =====================================================

        except requests.exceptions.Timeout:

            print()

            print(
                "❌ Ollama request timed out."
            )


        # =====================================================
        # GENERAL ERROR
        # =====================================================

        except Exception as e:

            print()

            print(
                f"❌ Error: {e}"
            )


# ============================================================
# START AILOA
# ============================================================

if __name__ == "__main__":

    main()