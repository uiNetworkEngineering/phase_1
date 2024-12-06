# packet_sniffer.py
from scapy.all import sniff, Raw
from scapy.layers.inet import IP

class PacketSniffer:
    def __init__(self, identifier, src_ip="127.0.0.1", dst_ip="127.0.0.1", iface=r"\Device\NPF_Loopback"):
        self.identifier = identifier
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.iface = iface

    def process_packet(self, packet):
        """Processes the captured packet and checks if it matches the identifier."""
        if packet.haslayer(IP) and packet.haslayer(Raw):
            raw_data = packet[Raw].load
            # Check if the packet contains the identifier
            if raw_data.startswith(self.identifier):
                print(f"Received matching packet: {packet[IP].src} -> {packet[IP].dst}")
                print(f"Identifier: {raw_data[:len(self.identifier)]}")
                print(f"File Content: {raw_data[len(self.identifier):].decode(errors='ignore')}")

    def start_sniffing(self):
        """Starts sniffing packets on the specified interface."""
        print("Sniffer is running, waiting for matching packets...")
        sniff(prn=self.process_packet, filter="ip", store=0, iface=self.iface)


# Main execution flow
if __name__ == "__main__":
    # Define the identifier that you want to capture
    identifier = b"UniquePacket12345"

    # Create a PacketSniffer instance and start sniffing for the sent packet
    sniffer = PacketSniffer(identifier)
    sniffer.start_sniffing()
