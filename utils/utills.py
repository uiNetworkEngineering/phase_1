import logging
import struct

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def checksum(data):
    """Calculate the one's complement checksum."""
    # Ensure the length of data is even by padding with a zero byte if odd
    if len(data) % 2 == 1:
        data += b'\0'

    # Zero out the checksum field (last 2 bytes of the IP header, 20 bytes total)
    # In a real IP header, the checksum would be set to 0 for calculation
    data = data[:10] + b'\x00\x00' + data[12:]

    # Unpack the data into 16-bit words
    unpacked_data = struct.unpack('!%sH' % (len(data) // 2), data)

    # Sum the 16-bit words
    s = sum(unpacked_data)

    # Add the carry bits (if any) and fold the sum into 16 bits
    s = (s >> 16) + (s & 0xFFFF)

    # Add carry if necessary (in case we have another overflow)
    s += (s >> 16)

    # Return the one's complement of the sum
    result = ~s & 0xFFFF

    return result
