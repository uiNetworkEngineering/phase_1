import multiprocessing
import time

from scapy.layers.inet import IP
from scapy.sendrecv import sniff, send

from utils.control_layer import CustomLayer
from utils.utills import LoggerService, PacketService, PacketHandler


class PacketSender:
    def __init__(self, file_path, identifier, dst_ip="127.0.0.1", src_ip="127.0.0.1", ttl=64, logger_service=None, packet_service=None, chunks_length= 20,seq_number= 1):
        self.file_path = file_path
        self.id = identifier
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.ttl = ttl
        self.logger_service = logger_service or LoggerService()
        self.packet_service = packet_service or PacketService(self.logger_service)
        self.packet_received = False  # Track if the packet has been received
        self.chunks_length = chunks_length
        self.seq_number = seq_number
        self.chunks = []
        self.chunk_number = 0

        self.process = None

        manager = multiprocessing.Manager()
        self.dict = manager.dict()


    @staticmethod
    def time_exceeded(self,dict):
        while True:
            time.sleep(1)
            if dict and not dict.get('packet_received') and dict.get('ack') == 0 and dict.get('last_packet'):
                self.packet_service.send_packet(dict['last_packet'])

    def send_packet(self):
        """Reads the file, creates the inner packet, wraps it in another packet, and sends it."""
        file_data = PacketHandler.read_file(self.file_path)
        if not file_data:
            self.logger_service.log_error(f"Error: No data to send from the file '{self.file_path}'")
            return

        if len(file_data) > self.chunks_length:
            self.chunks = [file_data[i:i + self.chunks_length] for i in range(0, len(file_data), self.chunks_length)]

            # Print the chunks
            outer_packet = self.packet_service.create_outer_packet(self.src_ip, self.dst_ip, self.ttl, self.chunks[self.chunk_number],
                                                                       self.id,1,1)

            self.packet_service.send_packet(outer_packet)
            self.dict['last_packet'] = outer_packet
            self.dict['ack'] = 0


        else:
            outer_packet = self.packet_service.create_outer_packet(self.src_ip, self.dst_ip, self.ttl, file_data,
                                                                   self.id,0,0)
            self.packet_service.send_packet(outer_packet)
            self.dict['last_packet'] = outer_packet
            self.dict['ack'] = 0

    def start_sniffing(self):
        """Starts sniffing packets on the specified interface."""
        self.logger_service.log_info(f"Packet sent, looking for inner packet with ID: {self.id}...")
        try:
            sniff(prn=self.get_inner_packet, filter="ip", store=0, iface=r"\Device\NPF_Loopback", stop_filter=self.should_stop_sniffing)
        except Exception as e:
            self.logger_service.log_error(f"Error sniffing packets: {e}")

    def get_inner_packet(self, packet):
        """Extract the inner packet from the sniffed outer packet."""
        if packet.haslayer(IP) and packet[IP].id == 65534:
            self.dict['ack'] = 1
            self.seq_number += 1
            self.chunk_number += 1

            ip_header = packet[IP]
            raw_ip_header = bytes(ip_header)[:20]  # First 20 bytes for the IPv4 header

            # Validate checksum
            if self.packet_service.validate_checksum(packet, raw_ip_header):
                custom_layer = CustomLayer(ip_header.load)
                inner_packet = custom_layer.load

                self.logger_service.log_info(f"Retrieved packet: {inner_packet}")
                # Print the chunks
                if self.chunk_number < len(self.chunks) - 1:
                    outer_packet = self.packet_service.create_outer_packet(self.src_ip, self.dst_ip, self.ttl,
                                                                           self.chunks[self.chunk_number],
                                                                           self.id, 1, self.seq_number)
                    self.packet_service.send_packet(outer_packet)
                    self.dict['last_packet'] = outer_packet
                    self.dict['ack'] = 0

                elif self.chunk_number == len(self.chunks) - 1:
                    outer_packet = self.packet_service.create_outer_packet(self.src_ip, self.dst_ip, self.ttl,
                                                                           self.chunks[self.chunk_number],
                                                                           self.id, 0, self.seq_number)
                    self.packet_service.send_packet(outer_packet)
                    self.dict['last_packet'] = outer_packet
                    self.dict['ack'] = 0
                if custom_layer.more_chunk == 0:
                    self.packet_received = True  # Mark that the packet was received
                    self.dict['packet_received'] = True
                    self.process.terminate()

            else:
                self.logger_service.log_error(f"Checksum mismatch for packet ID: {self.id}")

    def should_stop_sniffing(self, packet):
        """Condition to stop sniffing once the inner packet is received."""
        return self.packet_received


if __name__ == "__main__":
    file_path = "sample.txt"  # Replace with your file path
    id = 65535  # Unique identifier (as an example)

    sender = PacketSender(file_path, id)
    sender.process = multiprocessing.Process(target=PacketSender.time_exceeded, args=(sender,sender.dict,))
    sender.send_packet()
    sender.process.start()
    sender.start_sniffing()
