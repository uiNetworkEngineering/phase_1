from scapy.all import sniff, Raw

from utils.custom_protocol_header import CustomProtocolHeader
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

                # Unwrap the inner custom protocol packet
                inner_raw_data = outer_file_data  # The raw data of the inner packet
                inner_custom_header = CustomProtocolHeader.from_bytes(inner_raw_data[:12])
                inner_payload = inner_raw_data[12:]

                # Validate inner packet checksum
                if CustomHeader.checksum(inner_payload) != inner_custom_header.checksum:  # Validate using checksum
                    return

                if inner_custom_header.protocol_id == self.expected_identifier:
                    logger.info(f"Inner packet detected with Protocol ID: {inner_custom_header.protocol_id}, "
                                f"Seq: {inner_custom_header.sequence_number}")
                    print(f"File Content from inner packet: {inner_payload.decode(errors='ignore')}")

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
