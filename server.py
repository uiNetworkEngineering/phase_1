from scapy.all import sniff, Raw
from scapy.layers.inet import IP

# Define the packet processing function
def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(Raw):
        # Get the raw payload (identifier + file content)
        raw_data = packet[Raw].load
        # Define the identifier you're looking for
        identifier = b"UniquePacket12345"

        # Check if the packet contains the identifier
        if raw_data.startswith(identifier):
            print(f"Received matching packet: {packet[IP].src} -> {packet[IP].dst}")
            print(f"Identifier: {raw_data[:len(identifier)]}")
            print(f"File Content: {raw_data[len(identifier):].decode(errors='ignore')}")

# Start sniffing for raw IP packets on the loopback interface, with a filter for 127.0.0.1
print("Sniffer is running, waiting for matching packets...")
sniff(prn=process_packet, filter="ip", store=0, iface=r"\Device\NPF_Loopback")  # Adjust iface as necessary
