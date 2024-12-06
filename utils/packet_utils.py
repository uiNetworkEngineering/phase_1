# packet_utils.py
import time

from scapy.layers.inet import IP
from scapy.packet import Raw


class CustomHeader:
    def __init__(self, identifier, timestamp=None, seq_num=None):
        """Initializes the custom header with identifier, timestamp, and sequence number."""
        self.identifier = identifier
        self.timestamp = timestamp if timestamp else int(time.time())  # Default to current timestamp
        self.seq_num = seq_num if seq_num else 1  # Default sequence number is 1

    def build_header(self):
        """Constructs the custom header."""
        header = self.identifier.to_bytes(4, byteorder='big')  # 4-byte identifier
        header += self.timestamp.to_bytes(4, byteorder='big')  # 4-byte timestamp
        header += self.seq_num.to_bytes(4, byteorder='big')  # 4-byte sequence number
        return header

    @classmethod
    def from_bytes(cls, header_bytes):
        """Convert raw bytes into a CustomHeader instance."""
        identifier = int.from_bytes(header_bytes[:4], byteorder='big')
        timestamp = int.from_bytes(header_bytes[4:8], byteorder='big')
        seq_num = int.from_bytes(header_bytes[8:12], byteorder='big')
        return cls(identifier, timestamp, seq_num)

class PacketHandler:
    @staticmethod
    def create_packet(src_ip, dst_ip, ttl, file_data, identifier, seq_num=1):
        """Creates an IP packet with a custom header and file data."""
        custom_header = CustomHeader(identifier, seq_num=seq_num)
        header = custom_header.build_header()
        combined_payload = header + file_data  # Prepend header to the file data
        return IP(src=src_ip, dst=dst_ip, ttl=ttl) / Raw(combined_payload)

    @staticmethod
    def read_file(file_path):
        """Reads the content of the file."""
        with open(file_path, "rb") as f:
            return f.read()
