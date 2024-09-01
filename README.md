# Code_Alpha_Cyber_Projects-
from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP Packet: {ip_src} -> {ip_dst}")
        
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"TCP Segment: {tcp_sport} -> {tcp_dport}")
        print("-" * 40)

print("Starting network sniffer...")
sniff(filter="ip", prn=packet_callback, timeout=30)


