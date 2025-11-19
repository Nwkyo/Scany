#!/usr/bin/env python3
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from .utils import get_timing_template, detect_service

class TCPScanner:
    def __init__(self, target, ports, timing_level=3):
        self.target = target
        self.ports = ports
        self.timeout, self.max_concurrent = get_timing_template(timing_level)
        self.results = {}
        self.lock = threading.Lock()

    def scan_port(self, port):
        """扫描单个端口并尝试识别服务"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                # 端口开放，尝试获取服务信息
                service = detect_service(self.target, port, self.timeout)
                with self.lock:
                    self.results[port] = {'state': 'open', 'service': service}
            else:
                with self.lock:
                    self.results[port] = {'state': 'closed', 'service': 'n/a'}
            sock.close()
        except socket.timeout:
            with self.lock:
                self.results[port] = {'state': 'filtered', 'service': 'n/a'}  # 超时通常表示端口被过滤
        except socket.error as e:
            # 根据错误类型判断是关闭还是过滤
            error_code = e.errno if hasattr(e, 'errno') else None
            if error_code in [10061, 111]:  # 连接被拒绝
                with self.lock:
                    self.results[port] = {'state': 'closed', 'service': 'n/a'}
            else:
                with self.lock:
                    self.results[port] = {'state': 'filtered', 'service': 'n/a'}

    def scan(self):
        """扫描指定的端口范围"""
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            executor.map(self.scan_port, self.ports)

        end_time = time.time()
        print(f"Scan completed in {end_time - start_time:.2f} seconds")
        return self.results

        # 返回所有端口的状态
        return self.results