import time
import os
from scapy.layers.inet import IP
from scapy.all import Raw

from utils.custom_protocol_header import CustomProtocolHeader
from utils.packet_utils import logger, CustomHeader


class PacketHandler:
    """Class for handling packet operations like file reading and packet creation."""

    @staticmethod
    def read_file(file_path):
        """Reads the content of a file and returns its data."""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return b""
            with open(file_path, "rb") as f:
                file_data = f.read()
            logger.info(f"File '{file_path}' read successfully.")
            return file_data
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return b""

    @staticmethod
    def create_packet(src_ip, dst_ip, ttl, file_data, identifier, seq_num,checksum):
        """Creates an IP packet with a custom header and the file data."""
        timestamp = int(time.time())
        header = CustomHeader(identifier, timestamp, seq_num,checksum).build_header()
        combined_payload = header + file_data
        return IP(src=src_ip, dst=dst_ip, ttl=ttl) / Raw(combined_payload)

    @staticmethod
    def create_custom_packet(protocol_id, seq_num, file_data):
        """Creates a custom protocol packet with a header and the file data."""
        length = len(file_data)
        # Calculate checksum for the payload
        payload_checksum = CustomHeader.checksum(file_data)
        header = CustomProtocolHeader(protocol_id, length, payload_checksum, seq_num).build_header()
        combined_payload = header + file_data
        return combined_payload