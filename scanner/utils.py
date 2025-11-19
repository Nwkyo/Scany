#!/usr/bin/env python3
import re
import socket
import ipaddress

def resolve_target(target):
    """解析目标，支持IP地址和域名"""
    try:
        # 一开始先验证域名
        socket.gethostbyname(target)
        return target
    except ValueError:
        try:
            # IP直接验证
            ipaddress.ip_address(target)
            return target
        except socket.gaierror:
            return None

def get_banner(ip, port, timeout=2):
    """尝试获取服务banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # 根据常见端口发送不同的探测请求
        if port == 80 or port == 443 or port == 8080 or port == 8443:
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        elif port == 21:
            sock.send(b'USER anonymous\r\n')
        elif port == 22:
            # SSH服务通常会主动发送banner
            pass
        elif port == 23:
            sock.send(b'\r\n')
        elif port == 25 or port == 465 or port == 587:
            sock.send(b'HELO example.com\r\n')
        elif port == 53:
            # DNS查询
            pass
        elif port == 110 or port == 995:
            sock.send(b'USER anonymous\r\n')
        elif port == 143 or port == 993:
            sock.send(b'LOGIN anonymous\r\n')
        elif port == 3306:
            # MySQL
            pass
        elif port == 3389:
            # RDP
            pass
        else:
            # 默认发送一个空请求
            sock.send(b'\r\n')
        
        banner = sock.recv(1024).decode(errors='replace').strip()
        sock.close()
        return banner
    except:
        return None

def detect_service(ip, port, timeout=2):
    """检测服务和版本信息"""
    banner = get_banner(ip, port, timeout)
    if not banner:
        return "unknown"
    
    # 简单的服务识别
    if 'HTTP' in banner:
        # 尝试提取Server头部
        lines = banner.split('\r\n')
        status_line = lines[0]
        server_line = next((line for line in lines if line.lower().startswith('server: ')), None)
        
        if server_line:
            return f'HTTP: {server_line[8:]}'
        else:
            return f'HTTP: {status_line}'
    elif 'SSH' in banner:
        return f'SSH: {banner.split("\r\n")[0]}'
    elif 'FTP' in banner or '220 ' in banner:
        return f'FTP: {banner.split("\r\n")[0]}'
    elif 'SMTP' in banner or '220 ' in banner:
        return f'SMTP: {banner.split("\r\n")[0]}'
    elif 'POP3' in banner or '+OK' in banner:
        return f'POP3: {banner.split("\r\n")[0]}'
    elif 'IMAP' in banner or '* OK' in banner:
        return f'IMAP: {banner.split("\r\n")[0]}'
    else:
        return f'unknown: {banner[:60]}...'

def get_timing_template(timing_level):
    """根据时间模板级别返回相应的超时和并发设置"""
    # 时间模板: (timeout, max_concurrent)
    templates = {
        1: (10, 1),    # 最慢, 最准确
        2: (5, 5),
        3: (2, 10),    # 默认
        4: (1, 20),
        5: (0.5, 50)   # 最快, 可能不准确
    }
    return templates.get(timing_level, templates[3])