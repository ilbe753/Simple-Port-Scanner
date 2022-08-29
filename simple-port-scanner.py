#!/usr/local/bin/python
from scapy.all import *
import os
import argparse

# TCP SYN SCAN
def tcp_syn_scan(dst_ip, dst_ports, TTL_VALUE, SOURCE_PORT, TCP_WINDOW_SIZE, SEQ_NUM):
    print("TCP SYN Scan: {0} ports {1}".format(dst_ip, dst_ports))
    #src_port = RandShort()
    for dst_port in dst_ports:
        packet = sr1(IP(dst=dst_ip, ttl=TTL_VALUE)/TCP(sport=SOURCE_PORT, dport=dst_port, flags="S", window=TCP_WINDOW_SIZE, seq=SEQ_NUM), timeout=1, verbose=0)
        if packet != None:
            if packet.haslayer(TCP):
                if packet[TCP].flags == 20:
                    print("{0}: Closed".format(dst_port))
                elif packet[TCP].flags == 18:
                    print("{0}: Open".format(dst_port))
                else:
                    print("{0}: TCP packet resp / filtered".format(dst_port))
            elif packet.haslayer(ICMP):
                print("{0}: ICMP resp / filtered".format(dst_port))
            else:
                print("{0}: Unknown resp".format(dst_port))
                print(packet.summary())
        else:
            print("{0}: Unanswered".format(dst_port))


# TCP XMAS SCAN
def tcp_xmas_scan(dst_ip, dst_ports, TTL_VALUE, SOURCE_PORT, TCP_WINDOW_SIZE, SEQ_NUM):
    print("TCP XMAS Scan: {0}, ports {1}".format(dst_ip, dst_ports))
    #src_port = RandShort()
    for dst_port in dst_ports:
        packet = sr1(IP(dst=dst_ip)/TCP(sport=SOURCE_PORT, dport=dst_port, flags="FPU", window=TCP_WINDOW_SIZE, seq=SEQ_NUM), timeout=1, verbose=0)
        if packet != None:
            if packet.haslayer(TCP):
                if packet[TCP].flags == 20:
                    print("{0}: Closed".format(dst_port))
                else:
                    print("{0}: TCP flag %s".format(dst_port, packet[TCP].flag))
            elif packet.haslayer(ICMP):
                print("{0}: ICMP resp / filtered".format(dst_port))
            else:
                print("{0}: Unknown resp".format(dst_port))
                print(packet.summary())
        else:
            print("{0}: Open / filtered".format(dst_port))


# TCP FIN SCAN
def tcp_fin_scan(dst_ip, dst_ports, TTL_VALUE, SOURCE_PORT, TCP_WINDOW_SIZE, SEQ_NUM):
    print("TCP FIN Scan: {0}, ports {1}".format(dst_ip, dst_ports))
    #src_port = RandShort()
    for dst_port in dst_ports:
        packet = sr1(IP(dst=dst_ip)/TCP(sport=SOURCE_PORT, dport=dst_port, flags="F", window=TCP_WINDOW_SIZE, seq=SEQ_NUM), timeout=1, verbose=0)
        if packet != None:
            if packet.haslayer(TCP):
                if packet[TCP].flags == 20:
                    print("{0}: Closed".format(dst_port))
                else:
                    print("{0}: TCP flag %s".format(dst_port, packet[TCP].flag))
            elif packet.haslayer(ICMP):
                print("{0}: ICMP resp / filtered".format(dst_port))
            else:
                print("{0}: Unknown resp".format(dst_port))
                print(packet.summary())
        else:
            print("{0}: Open / filtered".format(dst_port))



# TCP NULL SCAN                                                                                           
def tcp_null_scan(dst_ip, dst_ports, TTL_VALUE, SOURCE_PORT, TCP_WINDOW_SIZE, SEQ_NUM):
    print("TCP NULL Scan: {0}, ports {1}".format(dst_ip, dst_ports))
    #src_port = RandShort()
    for dst_port in dst_ports:
        packet = sr1(IP(dst=dst_ip)/TCP(sport=SOURCE_PORT, dport=dst_port, flags="", window=TCP_WINDOW_SIZE, seq=SEQ_NUM), timeout=1, verbose=0)
        if packet != None:
            if packet.haslayer(TCP):
                if packet[TCP].flags == 20:
                    print("{0}: Closed".format(dst_port))
                else:
                    print("{0}: TCP flag %s".format(dst_port, packet[TCP].flag))
            elif packet.haslayer(ICMP):
                print("{0}: ICMP resp / filtered".format(dst_port))
            else:
                print("{0}: Unknown resp".format(dst_port))
                print(packet.summary())
        else:
            print("{0}: Open / filtered".format(dst_port))


def tcp_connect_scan(dst_ip, dst_ports, TTL_VALUE, SOURCE_PORT, TCP_WINDOW_SIZE, SEQ_NUM):
    print("TCP Connect Scan: {0} ports {1}".format(dst_ip, dst_ports))

    os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

    #src_port = RandShort()
    for dst_port in dst_ports:
        packet = sr1(IP(dst=dst_ip, ttl=TTL_VALUE)/TCP(sport=SOURCE_PORT, dport=dst_port, flags="S", seq=SEQ_NUM, window=TCP_WINDOW_SIZE), timeout=1, verbose=0)
        if packet is not None:
            if packet.haslayer(TCP):
                if packet[TCP].flags == 0x12:
                    new_packet = sr1(IP(dst=dst_ip, ttl=TTL_VALUE)/TCP(sport=SOURCE_PORT, dport=dst_port, flags="A", seq=packet.ack, ack=(packet[TCP].seq + 1), window=TCP_WINDOW_SIZE), timeout=1, verbose=0)
                    print("Open")

    os.system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP")



# Argument parser
parser = argparse.ArgumentParser("[i] Simple Port Scanner")
parser.add_argument("-d", "--destination", help="Specify destination IP Address", required=True)
parser.add_argument("-p", "--ports", type=int, nargs="+", help="Specify destination ports (80 443 ...)")
parser.add_argument("-ps", "--portscantype", help="Port Scan type, tcp_syn_scan|tcp_connect_scan|tcp_xmas_scan|tcp_fin_scan|tcp_null_scan", required=True)
args = parser.parse_args()

# arg parsing
destination = args.destination
port_scan_type = args.portscantype.lower()
#host_discovery_type = args.hostdiscoverytype.lower()

if args.ports:
    ports = args.ports
else:
    # default port range
    ports = range(1, 1024)

TTL_VALUE = 59
SOURCE_PORT = 32767
TCP_WINDOW_SIZE = 65535
SEQ_NUM = 6550305


# port scan types
if port_scan_type == "tcp_syn_scan":
    tcp_syn_scan(destination, ports, TTL_VALUE, SOURCE_PORT, TCP_WINDOW_SIZE, SEQ_NUM)
elif port_scan_type == "tcp_connect_scan":
    tcp_connect_scan(destination, ports, TTL_VALUE, SOURCE_PORT, TCP_WINDOW_SIZE, SEQ_NUM)
elif port_scan_type == "tcp_xmas_scan":
    tcp_xmas_scan(destination, ports, TTL_VALUE, SOURCE_PORT, TCP_WINDOW_SIZE, SEQ_NUM)
elif port_scan_type == "tcp_fin_scan":
    tcp_fin_scan(destination, ports, TTL_VALUE, SOURCE_PORT, TCP_WINDOW_SIZE, SEQ_NUM)
elif port_scan_type == "tcp_null_scan":
    tcp_null_scan(destination, ports, TTL_VALUE, SOURCE_PORT, TCP_WINDOW_SIZE, SEQ_NUM)
else:
    print("Scan type not supported")

