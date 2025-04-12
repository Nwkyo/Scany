import re
import socket
import subprocess
import threading
import sys
import json
import platform
import argparse
from scan import scan
from os_detech import os_detech
### Options ###

parser = argparse.ArgumentParser()

parser.add_argument("target",help="target IP or Domain")
parser.add_argument("port",help="port to selected")
parser.add_argument("-s","--scan","--scanI",help="ICMP scan")
parser.add_argument("-sT","--scanT",help="TCP scan")
parser.add_argument("-sU","--scanU",help="UDP scan")
parser.add_argument("-pall","--port-all",help="scan all port")
parser.add_argument("-v","--version",help="version")
parser.add_argument("-o","--os",help="OS detection")

args = parser.parse_args()
### Global Config ###
scan_mode = {
    "scanI": args.scan,
    "scanT": args.scanT,
    "scanU": args.scanU,
    "os": args.os
}
scan_mode_extra = {
    "pall": args.port_all
}
target = args.target
port = args.port
PIPE = subprocess.PIPE

# def get_my_ip():
#     ip_addr = subprocess.run(["hostname","-I"],stdout=PIPE,stderr=PIPE)
#     tmps = ip_addr.stdout.decode().split(' ')
#     # check 1 to 3 in ip ,if they same,automatically get
#     for i in tmps:
#         if i.split('.')[0] and i.split('.')[1] and i.split('.')[2] == target.split('.')[0] and target.split('.')[1] and target.split('.')[2]:
#             return i
#         else:
#             return ip_addr.stdout.decode()[0]

def domain_to_ip(target):
    # domain_to_ip
    domain_pattern = re.compile(
        r'^(?:http[s]?://)?'  # 协议头
        r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})'  # 基础域名
        r'(?::\d+)?'  # 端口号
        r'(?:[/?#][^\s]*)?$',  # 路径参数
        re.IGNORECASE
    )
    if re.match(domain_pattern, target):
        try:
            clean_target = re.sub(r'^(?:http[s]?://)?', '', target)
            ip = socket.gethostbyname(clean_target)
            return ip
        except Exception as e:
            print(e)
            sys.exit(1)
    return target

def main(target):
    domain_to_ip(target)
    if scan_mode["scanI"]:
        scan.scanI(target)
    elif scan_mode["scanT"]:
        scan.scanT(target)
    elif scan_mode["scanU"]:
        scan.scanU(target)
    elif scan_mode["os"]:
        os_detech.os_detech(target)
    else:
        print("Please select scan mode")

if __name__ == '__main__':
    main(target)


