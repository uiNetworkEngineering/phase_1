import logging
import os
import struct

from scapy.fields import ShortField
from scapy.layers.inet import IP, IPOption
from scapy.packet import Raw, bind_layers
from scapy.sendrecv import send

from utils.control_layer import CustomLayer


class PacketHandler:
    """Handles packet operations like reading files, creating packets, etc."""

    def __init__(self, logger_service=None):
        self.logger_service = logger_service or LoggerService()

    @staticmethod
    def read_file(file_path):
        """Reads the content of a file and returns its data as bytes."""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            with open(file_path, "rb") as file:
                file_data = file.read()
            return file_data
        except Exception as e:
            raise Exception(f"Error reading file {file_path}: {e}")

    @staticmethod
    def create_packet(src_ip, dst_ip, ttl, file_data, identifier, chunk_number, seq_number):
        ip_packet = IP(src=src_ip, dst=dst_ip, ttl=ttl, version=4, id=identifier)

        if isinstance(file_data, IP):
            result = ip_packet / file_data
        else:
            control_layer = CustomLayer(chunk_number=chunk_number, load=file_data, seq_number=seq_number)
            result = ip_packet / control_layer

        calculated_checksum = checksum(bytes(result)[:20])
        result[IP].chksum = calculated_checksum

        return result

    def log_packet_info(self, packet):
        """Logs packet information for debugging."""
        self.logger_service.log_info(f"Packet created: {packet.summary()}")
        self.logger_service.log_debug(f"Packet details: {packet.show()}")

# Service to handle logging and error reporting
class LoggerService:
    def __init__(self, name=__name__):
        self.logger = logging.getLogger(name)
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

    def log_info(self, message):
        self.logger.info(message)

    def log_error(self, message):
        self.logger.error(message)

    def log_debug(self, message):
        self.logger.debug(message)


# Service for handling common packet operations
class PacketService:
    def __init__(self, logger_service):
        self.logger_service = logger_service

    def validate_checksum(self, packet, raw_ip_header):
        """Validate the checksum of the packet."""
        calculated_checksum = checksum(raw_ip_header)
        if int(calculated_checksum) != int(packet[IP].chksum):
            self.logger_service.log_error(f"Checksum mismatch: {packet[IP].chksum} != {calculated_checksum}")
            return False
        return True

    def create_outer_packet(self, src_ip, dst_ip, ttl, file_data, identifier, chunk_number, seq_number):
        """Creates the outer packet by wrapping the file data into an IP packet."""
        inner_packet = PacketHandler.create_packet(src_ip, dst_ip, ttl, file_data, identifier, chunk_number, seq_number)
        outer_packet_data = inner_packet
        return PacketHandler.create_packet(src_ip, dst_ip, ttl, outer_packet_data, identifier, 0, 0)

    def send_packet(self, packet):
        """Sends the packet."""
        try:
            send(packet)
        except Exception as e:
            self.logger_service.log_error(f"Error sending packet: {e}")


def checksum(data):
    """Calculate the one's complement checksum."""
    if len(data) % 2 == 1:
        data += b'\0'

    data = data[:10] + b'\x00\x00' + data[12:]  # Zero out checksum field
    unpacked_data = struct.unpack('!%sH' % (len(data) // 2), data)
    s = sum(unpacked_data)
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)

    return ~s & 0xFFFF