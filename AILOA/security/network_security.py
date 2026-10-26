import psutil
import socket


def get_interfaces():

    interfaces = psutil.net_if_addrs()

    result = []

    for interface, addresses in interfaces.items():

        for address in addresses:

            if address.family == socket.AF_INET:

                result.append({
                    "interface": interface,
                    "ip": address.address,
                    "netmask": address.netmask
                })

    return result


def get_active_connections():

    connections = psutil.net_connections(kind="inet")

    result = []

    for connection in connections:

        result.append({
            "local": str(connection.laddr),
            "remote": str(connection.raddr) if connection.raddr else "",
            "status": connection.status,
            "pid": connection.pid
        })

    return result


def get_listening_ports():

    connections = psutil.net_connections(kind="inet")

    ports = []

    for connection in connections:

        if connection.status == "LISTEN":

            ports.append({
                "address": str(connection.laddr),
                "pid": connection.pid
            })

    return ports


def network_security_check():

    return {
        "interfaces": get_interfaces(),
        "connections": get_active_connections(),
        "listening_ports": get_listening_ports()
    }


if __name__ == "__main__":

    result = network_security_check()

    print("=== Network Security Check ===")

    print("\nNetwork Interfaces:")

    for item in result["interfaces"]:
        print(
            f"{item['interface']} -> "
            f"{item['ip']}"
        )

    print("\nListening Ports:")

    for item in result["listening_ports"]:
        print(
            f"{item['address']} "
            f"PID={item['pid']}"
        )

    print("\nActive Connections:")

    for item in result["connections"][:20]:

        print(
            f"{item['local']} -> "
            f"{item['remote']} "
            f"{item['status']}"
        )
