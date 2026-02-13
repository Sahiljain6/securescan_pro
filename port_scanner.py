import socket

def scan_ports(host):
    open_ports = []
    ports = [21, 22, 80, 443, 3306]

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((host, port)) == 0:
            open_ports.append(port)
        s.close()

    return open_ports
