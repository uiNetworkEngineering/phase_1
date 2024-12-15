import struct

from scapy.all import sniff
from scapy.layers.inet import IP, IPOption
from scapy.packet import Raw

from utils.control_layer import CustomLayer
from utils.utills import LoggerService, PacketService


class PacketSniffer:
    def __init__(self, id, src_ip="127.0.0.1", dst_ip="127.0.0.1", iface=r"\Device\NPF_Loopback", logger_service=None, packet_service=None):
        self.id = id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.iface = iface
        self.logger_service = logger_service or LoggerService()
        self.packet_service = packet_service or PacketService(self.logger_service)
        self.packet_received = False  # Track if the packet has been received

    def process_packet(self, packet):
        """Processes the captured packet, unwraps it, and checks for the custom header."""
        if packet.haslayer(IP) and packet[IP].id == self.id:
            outer_packet = packet[IP]
            raw_ip_header = bytes(outer_packet)[:20]  # First 20 bytes for the IPv4 header

            # Validate checksum
            if self.packet_service.validate_checksum(packet, raw_ip_header):
                custom_layer = CustomLayer(packet[IP].load)
                # custom_layer.show()
                inner_packet = custom_layer.load
                ip_packet = IP(inner_packet)
                ip_packet.show()
                self.packet_service.send_packet(ip_packet)
                self.packet_received = True  # Mark the packet as received
            else:
                self.logger_service.log_error(f"Invalid checksum for packet ID: {self.id}")

    def start_sniffing(self):
        """Starts sniffing packets on the specified interface."""
        self.logger_service.log_info(f"Sniffer is running, looking for outer packet with ID: {self.id}...")
        try:
            # Use `sniff` with stop_filter condition to stop once the packet is received
            sniff(prn=self.process_packet, filter="ip", store=0, iface=self.iface, stop_filter=self.should_stop_sniffing)
        except Exception as e:
            self.logger_service.log_error(f"Error sniffing packets: {e}")

    def should_stop_sniffing(self, packet):
        """Stops sniffing once the outer packet is received and processed."""
        return self.packet_received

    def stop_condition(self, packet):
        """Stops sniffing if the packet is empty or malformed."""
        if not packet:
            return True
        try:
            # Check if packet is valid (length > 0)
            if len(packet) < 4:  # Simple safeguard against malformed packets
                self.logger_service.log_warning(f"Skipping malformed packet: {packet}")
                return False
            return False
        except Exception as e:
            self.logger_service.log_warning(f"Error processing packet: {e}")
            return False


if __name__ == "__main__":
    id = 65535  # The identifier to filter on
    sniffer = PacketSniffer(id)
    sniffer.start_sniffing()
