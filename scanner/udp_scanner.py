#!/usr/bin/env python3
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from .utils import get_timing_template

class UDPScanner:
    def __init__(self, target, ports, timing_level=3):
        self.target = target
        self.ports = ports
        self.timeout, self.max_concurrent = get_timing_template(timing_level)
        self.results = {}
        self.lock = threading.Lock()

    def scan_port(self, port):
        """扫描单个UDP端口"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # 发送UDP探测包
            # 对于不同的UDP服务，我们可以发送不同的探测数据
            # 这里使用简单的DNS查询格式作为默认探测
            probe_data = b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
            
            # 对于特定端口使用不同的探测数据
            if port == 53:
                # DNS查询
                probe_data = b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
            elif port == 69:
                # TFTP请求
                probe_data = b'\x00\x01test.txt\x00octet\x00'
            elif port == 123:
                # NTP请求 (简单的客户端请求)
                probe_data = b'\x1b' + 47 * b'\x00'
            elif port == 161:
                # SNMP请求 (简单的get请求)
                probe_data = b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x5a\x4d\x6e\x80\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
            
            # 发送探测包
            sock.sendto(probe_data, (self.target, port))
            
            try:
                # 尝试接收响应
                data, addr = sock.recvfrom(1024)
                # 识别服务类型
                service = self._identify_service(port, data)
                # 有响应表示端口开放或过滤
                with self.lock:
                    self.results[port] = {'state': 'open|filtered', 'service': service}
            except socket.timeout:
                # 无响应，可能是关闭或过滤
                with self.lock:
                    self.results[port] = {'state': 'closed|filtered', 'service': 'n/a'}
            
            sock.close()
        except socket.error as e:
            with self.lock:
                self.results[port] = {'state': 'error', 'service': f'Error: {str(e)}'}

    def _identify_service(self, port, data):
        """根据端口和响应数据识别UDP服务类型"""
        # 基于端口的初步识别
        service_map = {
            53: 'DNS',
            69: 'TFTP',
            123: 'NTP',
            161: 'SNMP',
            162: 'SNMP-trap',
            520: 'RIP',
            521: 'RIPng',
            1900: 'SSDP',
            5353: 'MDNS'
        }

        # 默认服务名称
        service = service_map.get(port, 'udp-service')

        # 基于响应数据特征进一步识别
        if port == 53 and data:
            # DNS响应通常以2字节ID开头，且响应标志位有特定格式
            if len(data) >= 2 and (data[2] & 0x80):
                service = 'DNS (response)' 
        elif port == 123 and data:
            # NTP响应通常是48字节
            if len(data) == 48:
                service = 'NTP'
        elif port == 161 and data:
            # SNMP响应通常以0x30开头
            if data.startswith(b'\x30'):
                service = 'SNMP'

        return service

    def scan(self):
        """扫描指定的UDP端口范围"""
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            executor.map(self.scan_port, self.ports)

        end_time = time.time()
        print(f"Scan completed in {end_time - start_time:.2f} seconds")
        return self.results