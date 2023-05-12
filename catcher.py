#!/usr/bin/env python

from scapy.all import *
import sys

def main(pcap_file):
    packets = rdpcap(pcap_file)
    ips_ports = set()
    attacker_ip = ""
    victim_ip = ""
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if attacker_ip == "":
                attacker_ip = src_ip
                victim_ip = dst_ip
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                ips_ports.add(f"{src_ip}:{src_port}")
                ips_ports.add(f"{dst_ip}:{dst_port}")
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                ips_ports.add(f"{src_ip}:{src_port}")
                ips_ports.add(f"{dst_ip}:{dst_port}")
    with open("IPs-ports.txt", "w") as f:
        f.write(f"victim: {victim_ip}\nattacker: {attacker_ip}\n\n")
        f.write("IP address:port\n")
        f.write("-" * 20 + "\n")
        for ip_port in sorted(ips_ports):
            f.write(f"{ip_port}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} pcap_file")
        sys.exit(1)
    main(sys.argv[1])
