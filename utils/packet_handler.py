import time
import os
from scapy.layers.inet import IP
from scapy.all import Raw

from utils.packet_utils import CustomHeader
from utils.utills import  logger


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
