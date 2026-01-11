from scapy.all import sniff,DNS, DNSQR,IP
from datetime import datetime
from storage import add_traffic
listeners = []

def register_listener(callback):
    listeners.append(callback)

def notify(ip):
    for cb in listeners:
        cb(ip)

def process_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet.haslayer(IP):
        ip = packet[IP].src
        domain = packet[DNSQR].qname.decode(errors='ignore').rstrip('.')
        time = datetime.now().strftime("%H:%M:%S")

        add_traffic(ip, domain, time)
        notify(ip)

def start_sniffing():
    sniff(filter="udp port 53", prn=process_packet, store=False)