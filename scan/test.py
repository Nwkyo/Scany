import json
tcp_common = json.load(open("TCP_port_as_services.json", "r"))
tcp_service_port = list(tcp_common["port_as_services"].values())
tcp_service_name = list(tcp_common["port_as_services"].keys())
udp_common = json.load(open("UDP_port_as_services.json", "r"))
udp_service_port = list(tcp_common["port_as_services"].values())
udp_service_name = list(tcp_common["port_as_services"].keys())

def test():
    for tcp_port in tcp_service_port:
            print(tcp_port)
    for tcp_name in tcp_service_name:
            print(tcp_name)

    for udp_port in udp_service_port:
            print(udp_port)
    for udp_name in udp_service_name:
            print(udp_name)

if __name__ == "__main__":
    test()