import logging
from scapy.layers.inet import IP
from scapy.all import sniff, Raw
from utils.packet_utils import CustomHeader, logger
from utils.utills import checksum


class PacketSniffer:
    def __init__(self, expected_identifier, src_ip="127.0.0.1", dst_ip="127.0.0.1", iface=r"\Device\NPF_Loopback"):
        self.expected_identifier = expected_identifier
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.iface = iface

    def process_packet(self, packet):
        """Processes the captured packet, unwraps it, and checks for the custom header."""
        if packet.haslayer(IP):
            if packet[IP].id == 65535:
                ip_header = packet[IP]
                raw_ip_header = bytes(ip_header)[:20]  # First 20 bytes for the IPv4 header

                # Set the checksum field to 0 to calculate the checksum
                raw_ip_header = raw_ip_header[:10] + b'\x00\x00' + raw_ip_header[12:]  # Clear the checksum field (bytes 10-11)

                # Calculate the checksum over the header (excluding the checksum field)
                calculated_checksum = checksum(raw_ip_header)

                if int(calculated_checksum) == int(packet[IP].chksum):
                    inner_packet = ip_header.load
                    print(inner_packet)
                else:
                    print(packet[IP].chksum)
                    print(calculated_checksum)

    def start_sniffing(self):
        """Starts sniffing packets on the specified interface."""
        print(f"Sniffer is running, looking for outer packet with ID: {self.expected_identifier}...")
        try:
            sniff(prn=self.process_packet, filter="ip", store=0, iface=self.iface)
        except Exception as e:
            logger.error(f"Error sniffing packets: {e}")
            print(f"Error sniffing packets: {e}")


if __name__ == "__main__":
    expected_identifier = '08b65b5117a67eca'  # The identifier to filter on
    sniffer = PacketSniffer(expected_identifier)
    sniffer.start_sniffing()