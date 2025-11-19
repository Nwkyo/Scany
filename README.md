# Scany

Scany是一个用Python编写的网络扫描工具，类似于nmap，支持TCP端口扫描等功能。

## 功能特点
- TCP连接扫描
- UDP扫描
- 域名解析支持（可直接扫描域名）
- 自定义端口范围
- 可调节扫描速度
- 结果保存到文件
- 显示所有端口状态（开放、关闭、过滤）
- 提供端口状态统计摘要
- 服务和版本探测（支持常见服务识别）

## 安装

1. 确保已安装Python 3.6或更高版本
2. 克隆或下载此项目
3. 安装依赖（可选，当前版本无外部依赖）

```bash
cd scany
pip install -r requirements.txt
```

## 使用方法

### 基本用法
```bash
python scany.py -t scanme.nmap.org
```
这将执行默认的TCP连接扫描。
工具将自动解析域名为IP地址并进行扫描。

### UDP扫描
```bash
python scany.py -t 192.168.1.1 -sU
```
指定UDP端口范围:
```bash
python scany.py -t 192.168.1.1 -p 53,69,123,161 -sU
```

### 指定端口范围
```bash
python scany.py -t 192.168.1.1 -p 80,443,8080
```
或
```bash
python scany.py -t 192.168.1.1 -p 1-1000
```

### 指定扫描速度
使用-T参数指定扫描速度（1-5，5最快）：
```bash
python scany.py -t 192.168.1.1 -T 4
```

### 保存结果到文件
```bash
python scany.py -t 192.168.1.1 -o results.txt
```

## 示例输出

### 默认端口扫描输出
```
Scanning 192.168.1.1...
Scan completed in 5.23 seconds

Scan results:
Summary: 2 open, 17 closed, 1 filtered ports

Port details:
Port 21: closed - n/a
Port 22: closed - n/a
Port 23: closed - n/a
Port 25: closed - n/a
Port 53: closed - n/a
Port 80: open - HTTP: HTTP/1.0 200 OK (Server: ExampleServer/1.0)
Port 110: closed - n/a
Port 143: closed - n/a
Port 443: open - HTTP: HTTP/1.0 200 OK (Server: ExampleServer/1.0)
Port 465: closed - n/a
...
```

### 指定端口扫描输出
```
Scanning 192.168.1.1 on ports 80,443...
Scan completed in 2.15 seconds

Scan results:
Summary: 2 open, 0 closed, 0 filtered ports

Port details:
Port 80: open - HTTP: HTTP/1.0 200 OK
Port 443: open - HTTP: HTTP/1.0 200 OK
```
Port 1433: filtered
...

Results saved to results.txt
```

## 项目结构
```
scany/
├── scany.py         # 主程序入口
├── scanner/
│   ├── __init__.py
│   ├── tcp_scanner.py  # TCP扫描模块
│   └── utils.py        # 工具函数
├── README.md
└── requirements.txt
```

## 计划功能
- [ ] UDP扫描
- [ ] 操作系统检测
- [x] 服务版本检测（已实现）
- [ ] ARP扫描
- [ ] ICMP扫描
