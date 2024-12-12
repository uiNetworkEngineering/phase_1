from scapy.layers.inet import IP
from scapy.all import sniff, Raw
from utils.packet_utils import CustomHeader, logger

class PacketSniffer:
    def __init__(self, expected_identifier, src_ip="127.0.0.1", dst_ip="127.0.0.1", iface=r"\Device\NPF_Loopback"):
        self.expected_identifier = expected_identifier
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.iface = iface

    def process_packet(self, packet):
        """Processes the captured packet, unwraps it, and checks for the custom header."""
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            if len(raw_data) < 16:  # Ensure packet is large enough to contain header
                return

            # Unwrap the outer packet
            outer_header_bytes = raw_data[:16]
            outer_file_data = raw_data[16:]

            outer_custom_header = CustomHeader.from_bytes(outer_header_bytes)

            # Validate outer packet checksum
            if CustomHeader.checksum(outer_file_data) != outer_custom_header.checksum:  # Validate using checksum
                return

            if outer_custom_header.identifier == self.expected_identifier:
                logger.info(f"Outer packet detected with ID: {outer_custom_header.identifier}, "
                            f"Timestamp: {outer_custom_header.timestamp}, Seq: {outer_custom_header.seq_num}")
                print(f"Outer packet file content: {outer_file_data.decode(errors='ignore')}")

                # Unwrap the inner packet
                inner_packet = IP(outer_file_data)  # Create an IP packet from the inner packet payload
                if inner_packet.haslayer(Raw):
                    inner_raw_data = inner_packet[Raw].load
                    inner_header_bytes = inner_raw_data[:16]
                    file_content = inner_raw_data[16:].decode(errors='ignore')
                    inner_custom_header = CustomHeader.from_bytes(inner_header_bytes)

                    # Validate inner packet checksum
                    if CustomHeader.checksum(inner_raw_data[16:]) != inner_custom_header.checksum:  # Validate using checksum
                        logger.error("Inner packet checksum validation failed")
                        return

                    if inner_custom_header.identifier == self.expected_identifier:
                        logger.info(f"Inner packet detected with ID: {inner_custom_header.identifier}, "
                                    f"Timestamp: {inner_custom_header.timestamp}, Seq: {inner_custom_header.seq_num}")
                        print(f"File Content from inner packet: {file_content}")

    def start_sniffing(self):
        """Starts sniffing packets on the specified interface."""
        print(f"Sniffer is running, looking for outer packet with ID: {self.expected_identifier}...")
        try:
            sniff(prn=self.process_packet, filter="ip", store=0, iface=self.iface)
        except Exception as e:
            logger.error(f"Error sniffing packets: {e}")
            print(f"Error sniffing packets: {e}")

if __name__ == "__main__":
    expected_identifier = 12345678  # The identifier to filter on
    sniffer = PacketSniffer(expected_identifier)
    sniffer.start_sniffing()
