import struct


class CustomProtocolHeader:
    """Class representing the custom protocol header for the inner packet."""

    def __init__(self, protocol_id, length, checksum, sequence_number):
        self.protocol_id = protocol_id
        self.length = length
        self.checksum = checksum
        self.sequence_number = sequence_number

    def build_header(self):
        """Builds the custom protocol header as a byte string."""
        return struct.pack('!IHHI', self.protocol_id, self.length, self.checksum, self.sequence_number)

    @classmethod
    def from_bytes(cls, header_bytes):
        """Converts raw bytes into a CustomProtocolHeader instance."""
        protocol_id, length, checksum, sequence_number = struct.unpack('!IHHI', header_bytes)
        return cls(protocol_id, length, checksum, sequence_number)


