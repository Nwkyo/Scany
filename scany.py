#!/usr/bin/env python3
import argparse
import sys
from scanner.tcp_scanner import TCPScanner
from scanner.udp_scanner import UDPScanner
from scanner.utils import resolve_target

class Scany:
    # 定义类变量存储默认端口
    common_tcp_ports = '21,22,23,25,53,80,110,143,443,465,587,993,995,1723,3306,3389,5900,8080,8443'
    common_udp_ports = '53,67,68,69,123,161,162,1900,5353'

    def __init__(self):
        self.parser = argparse.ArgumentParser(description='Python network scanner similar to nmap')
        self._setup_arguments()

    def _setup_arguments(self):
        # 目标参数
        self.parser.add_argument('-t', '--target', required=True, help='Target IP address to scan')
        # 端口扫描参数
        self.parser.add_argument('-p', '--ports', default=self.common_tcp_ports, help=f'Port range to scan (e.g. 1-1024 or 80,443). Default for TCP: {self.common_tcp_ports}, Default for UDP: {self.common_udp_ports}')
        # 扫描类型
        self.parser.add_argument('-sT', action='store_true', help='TCP connect scan')
        self.parser.add_argument('-sU', action='store_true', help='UDP scan')
        # 扫描速度
        self.parser.add_argument('-T', type=int, choices=[1,2,3,4,5], default=3, help='Scan timing template (1-5, 5 is fastest)')
        # 输出参数
        self.parser.add_argument('-o', '--output', help='Save results to file')

    def parse_ports(self, ports_str):
        """解析端口范围字符串"""
        ports = []
        if ',' in ports_str:
            for p in ports_str.split(','):
                if '-' in p:
                    start, end = map(int, p.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(p))
        elif '-' in ports_str:
            start, end = map(int, ports_str.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(ports_str))
        return sorted(list(set(ports)))

    def run(self):
        args = self.parser.parse_args()

        # 解析目标（IP或域名）
        target_ip = resolve_target(args.target)
        if not target_ip:
            print(f"Error: Invalid target '{args.target}' (not a valid IP address or domain name)")
            sys.exit(1)
        
        # 显示解析结果
        if target_ip != args.target:
            # print(f"Resolved '{args.target}' to {target_ip}")
            pass

        # 确定要使用的默认端口
        if args.sU and args.ports == self.parser.get_default('ports'):
            # 如果是UDP扫描且未指定端口，使用UDP默认端口
            ports = self.parse_ports(self.common_udp_ports)
            # print(f"Scanning {target_ip} on common UDP ports ({self.common_udp_ports})...")
        elif args.ports == self.parser.get_default('ports'):
            # 如果是TCP扫描且未指定端口，使用TCP默认端口
            ports = self.parse_ports(self.common_tcp_ports)
            # print(f"Scanning {target_ip} on common TCP ports ({self.common_tcp_ports})...")
        else:
            # 解析用户指定的端口
            try:
                ports = self.parse_ports(args.ports)
                print(f"Scanning {target_ip} on ports {args.ports}...")
            except ValueError:
                print(f"Error: Invalid port range '{args.ports}'")
                sys.exit(1)

        # 检查是否使用默认端口
        if args.ports == self.parser.get_default('ports'):
            print(f"Scanning {target_ip}...")
        else:
            print(f"Scanning {target_ip} on ports {args.ports}...")

        # 根据扫描类型选择扫描器
        if args.sU:
            print("Running UDP scan...")
            scanner = UDPScanner(target_ip, ports, args.T)
            results = scanner.scan()
        elif args.sT:
            scanner = TCPScanner(target_ip, ports, args.T)
            results = scanner.scan()
        else:
            # 默认使用TCP connect扫描
            scanner = TCPScanner(target_ip, ports, args.T)
            results = scanner.scan()

        # 打印结果
        print("\nScan results:")
        if not results:
            print("No ports scanned.")
        else:
            # 统计不同状态的端口数量
            open_count = sum(1 for port_info in results.values() if 'open' in port_info['state'])
            closed_count = sum(1 for port_info in results.values() if 'closed' in port_info['state'])
            filtered_count = sum(1 for port_info in results.values() if 'filtered' in port_info['state'])
            
            print(f"Summary: {open_count} open, {closed_count} closed, {filtered_count} filtered ports")
            
            # 打印所有端口的状态
            print("\nPort details:")
            for port in sorted(results.keys()):
                state = results[port]['state']
                service = results[port]['service']
                print(f"Port {port}: {state} - {service}")

        # 保存结果到文件
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"Scan results for {args.target} ({target_ip}):\n\n")
                if not results:
                    f.write("No ports scanned.\n")
                else:
                    # 统计不同状态的端口数量
                    open_count = sum(1 for port_info in results.values() if 'open' in port_info['state'])
                    closed_count = sum(1 for port_info in results.values() if 'closed' in port_info['state'])
                    filtered_count = sum(1 for port_info in results.values() if 'filtered' in port_info['state'])
                    
                    f.write(f"Summary: {open_count} open, {closed_count} closed, {filtered_count} filtered ports\n\n")
                    
                    # 写入所有端口的状态
                    f.write("Port details:\n")
                    for port in sorted(results.keys()):
                        state = results[port]['state']
                        service = results[port]['service']
                        f.write(f"Port {port}: {state} - {service}\n")
            print(f"\nResults saved to {args.output}")

if __name__ == '__main__':
    scany = Scany()
    scany.run()