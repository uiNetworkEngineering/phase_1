from scapy.all import sniff, Raw
from utils.packet_utils import CustomHeader
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class PacketSniffer:
    def __init__(self, expected_identifier, src_ip="127.0.0.1", dst_ip="127.0.0.1", iface=r"\Device\NPF_Loopback"):
        self.expected_identifier = expected_identifier
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.iface = iface

    def process_packet(self, packet):
        """Processes the captured packet and checks for the custom header."""
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            if len(raw_data) < 12:  # Check if the packet is large enough to contain the header
                return

            # Extract the custom header (first 12 bytes)
            header_bytes = raw_data[:12]
            file_content = raw_data[12:].decode(errors='ignore')

            # Decode the custom header
            custom_header = CustomHeader.from_bytes(header_bytes)

            # Check if the identifier matches the expected one
            if custom_header.identifier == self.expected_identifier:
                logger.info(
                    f"Sent packet detected with ID: {custom_header.identifier}, Timestamp: {custom_header.timestamp}, Seq: {custom_header.seq_num}")
                print(f"File Content: {file_content}")

    def start_sniffing(self):
        """Starts sniffing packets on the specified interface."""
        print(f"Sniffer is running, looking for packet with ID: {self.expected_identifier}...")
        try:
            sniff(prn=self.process_packet, filter="ip", store=0, iface=self.iface)
        except Exception as e:
            logger.error(f"Error sniffing packets: {e}")
            print(f"Error sniffing packets: {e}")


# Main execution flow
if __name__ == "__main__":
    expected_identifier = 12345678  # The identifier to filter on
    sniffer = PacketSniffer(expected_identifier)
    sniffer.start_sniffing()
