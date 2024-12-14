from scapy.all import send
from scapy.layers.inet import IP
from scapy.sendrecv import sniff

from utils.packet_utils import PacketHandler, logger
from utils.utills import checksum


class PacketSender:
    def __init__(self, file_path, identifier, dst_ip="127.0.0.1", src_ip="127.0.0.1", ttl=64):
        self.file_path = file_path
        self.identifier = identifier
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.ttl = ttl

    def send_packet(self):
        """Reads the file, creates the inner packet, wraps it in another packet, and sends it."""
        file_data = PacketHandler.read_file(self.file_path)
        if not file_data:
            print(f"Error: No data to send from the file '{self.file_path}'")
            return

        # Create the inner packet
        inner_packet = PacketHandler.create_packet(self.src_ip, self.dst_ip, self.ttl, file_data, self.identifier)

        # Wrap the inner packet in another packet (outer packet)
        outer_packet_data = inner_packet.build()
        print(outer_packet_data[20:])  # Display the payload of the inner packet

        outer_packet = PacketHandler.create_packet(self.src_ip, self.dst_ip, self.ttl, outer_packet_data, self.identifier)

        try:
            send(outer_packet)
        except Exception as e:
            print(f"Error sending packet: {e}")
            logger.error(f"Error sending packet: {e}")
    def get_inner_packet(self,packet):
        if packet.haslayer(IP) and packet[IP].id == self.identifier:
            ip_header = packet[IP]
            raw_ip_header = bytes(ip_header)[:20]  # First 20 bytes for the IPv4 header

            # Clear the checksum field (bytes 10-11) and calculate the checksum
            raw_ip_header = raw_ip_header[:10] + b'\x00\x00' + raw_ip_header[12:]
            calculated_checksum = checksum(raw_ip_header)

            # Check if the calculated checksum matches the packet's checksum
            if int(calculated_checksum) == int(packet[IP].chksum):
                inner_packet = ip_header.load
                print(inner_packet)
            else:
                print(f"Checksum mismatch: {packet[IP].chksum} != {calculated_checksum}")
    def start_sniffing(self):
        """Starts sniffing packets on the specified interface."""
        print(f"packet sent, looking for inner packet with ID: {self.identifier}...")
        try:
            sniff(prn=self.get_inner_packet, filter="ip", store=0, iface=r"\Device\NPF_Loopback")
        except Exception as e:
            logger.error(f"Error sniffing packets: {e}")
            print(f"Error sniffing packets: {e}")


if __name__ == "__main__":
    file_path = "sample.txt"  # Replace with your file path
    identifier = 65535  # Unique identifier (as an example)

    sender = PacketSender(file_path, identifier)
    sender.send_packet()
    sender.start_sniffing()
