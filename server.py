from scapy.all import sniff, Raw
from scapy.layers.inet import IP

# Define the packet processing function
def process_packet(packet):
    if packet.haslayer(IP):
        # Check if the packet has the unique identifier in the payload
        if packet.haslayer(Raw) and b"UniquePacket12345" in packet[Raw].load:
            print(f"Received IP packet: {packet[IP].src} -> {packet[IP].dst}")
            print(f"Payload: {packet[Raw].load}")

# Start sniffing for raw IP packets on the loopback interface
print("Sniffer is running, waiting for packets...")
sniff(prn=process_packet, filter="ip", store=0, iface=r"\Device\NPF_Loopback")
