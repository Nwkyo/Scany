# from scapy.all import *
from scapy.layers.inet import *
import platform
# import socket
import subprocess
import json
from main import scan_mode
from main import scan_mode_extra
from main import target
from main import port
PIPE = subprocess.PIPE

with open("TCP_port_as_services.json", "r") as f:
    tcp_common = json.load(f)

with open("UDP_port_as_services.json", "r") as f:
    udp_common = json.load(f)

t_serv_port = list(tcp_common["port_as_services"].values())
u_serv_port = list(udp_common["port_as_services"].values())

t_serv_name = list(tcp_common["port_as_services"].keys())
u_serv_name = list(udp_common["port_as_services"].keys())

# Guessing My OS
myos = platform.system()
mykernel = platform.release()
version = json.load(open("../version.json", "r"))

# Getting my python version
pyver = platform.python_version()
class Port(target):
    def port_scan(target):
        print("[*] scaning port...")

        if port is None:
            for tcp_port in t_serv_port:
                s = sr1(IP(dst=target)/TCP(dport=tcp_port), timeout=1)

                if s is not None:
                    print(f"{tcp_port} is open")
                else:
                    print(f"{tcp_port} is closed")

            for udp_port in u_serv_port:
                s = sr1(IP(dst=target)/UDP(dport=udp_port), timeout=1)

                if s is not None:
                    print(f"{udp_port} is open")
                else:
                    print(f"{udp_port} is closed")
        else:

            s = sr1(IP(dst=target)/TCP(dport=port), timeout=1)

            if s is not None:
                if s is TCP:
                    print(f"{port} is open,service is {t_serv_port[t_serv_port.index(port)]}")
                if s in UDP:
                    print(f"{port} is open,service is {u_serv_port[u_serv_port.index(port)]}")
            else:
                print(f"{port} is closed")

    if scan_mode_extra["pall"]:
        for port in range(1,65535):
            s = sr1(IP(dst=target)/TCP(dport=port), timeout=1)
            if s is not None:
                if s is TCP:
                    print(f"{port} is open,service is {t_serv_port[t_serv_port.index(port)]}")
                if s in UDP:
                    print(f"{port} is open,service is {u_serv_port[u_serv_port.index(port)]}")
            else:
                print(f"{port} is closed")

class scanI(target):
    if not scan_mode["scanI"]:
        exit(1)
    print("[*] Scaning...")
    def scan(target):
        s = sr(IP(dst=target)/ICMP())
        if s:
            print(f"Scaned {target},scaning ports.")
            Port.port_scan(target)
        else:
            print(f"{target} is not reachable.Use -sT or -sU.")
            exit(1)

class scanT(target):
    def scan(target):
        s = sr1(IP(dst=target)/TCP(dport=port,flags="S"))
        f = sr1(IP(dst=target)/TCP(dport=port,flags="F"),timeout=1)
        if s or f:
            print(f"Scaned {target},scaning ports.")
            Port.port_scan(target)
        else:
            print(f"{target} is not reachable.")
            exit(1)

class scanU(target):
    def scan(target):
        s = sr1(IP(dst=target)/UDP(dport=port))
        if s:
            print(f"Scaned {target},scaning ports.")
            Port.port_scan(target)
        else:
            print(f"{target} is not reachable.")
            exit(1)