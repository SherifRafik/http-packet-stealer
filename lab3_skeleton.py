import socket
import struct
import binascii


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload

    # Getter for payload
    def get_payload(self):
        return self.payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    unpacked_ip = struct.unpack("!BBBB", raw_ip_addr)
    # map(function, iterable(tuple))
    # Convert every element in the tuple into a string using map
    ip_map = map(str, unpacked_ip)
    # Join all the strings in this map on .
    ip_as_string = ".".join((ip_map))
    return ip_as_string


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    return TcpPacket(-1, -1, -1, b'')


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section

    # First byte : Version(4 bits) + IHL(4 bits)
    version_and_ihl = ip_packet[0]
    # Extract the ihl by anding with 0f, time 4 because ihl is the length in 32 bit words
    internet_header_length = (version_and_ihl & 0x0f)
    # Nineth byte : Protocol (8 bits)
    protocol = ip_packet[9]

    # Source address start at byte 12 and ends at byte 16
    source_address = ip_packet[12:16]
    # Convert the address into a readable format
    source_address = parse_raw_ip_addr(source_address)
    # destination address start at byte 16 and ends at byte 20
    destination_address = ip_packet[16:20]
    # Convert the address into a readable format
    destination_address = parse_raw_ip_addr(destination_address)
    print(source_address, destination_address)
    payload = ip_packet[internet_header_length * 4:]

    return IpPacket(protocol, internet_header_length, source_address, destination_address, payload)


def setup_sockets():
    TCP = 0x06
    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, TCP)
    iface_name = "lo"
    stealer.setsockopt(socket.SOL_SOCKET,
                       socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))

    return stealer


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    stealer = setup_sockets()
    while True:
        # Receive packets and do processing
        raw_data, address = stealer.recvfrom(4096)
        print(binascii.hexlify(raw_data))
        ip_packet = parse_network_layer_packet(raw_data)
        tcp_packet = parse_application_layer_packet(ip_packet.get_payload())
        pass
    pass


if __name__ == "__main__":
    main()
