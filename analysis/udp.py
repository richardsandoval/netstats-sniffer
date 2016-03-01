import string
from struct import unpack

from analysis.packet import AbstractPacket


class UDP(AbstractPacket):
    def __init__(self, t, sniffer, packet, user):
        self.t = t
        self.sniffer = sniffer
        self.packet = packet
        self.user = user

    def send_udp_packet(self):
        udph_length = 8
        udp_header = self.packet[self.t:self.t + 8]
        # now unpack them :)
        udph = unpack('!HHHH', udp_header)

        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]
        h_size = self.t + udph_length
        data_size = len(self.packet) - h_size

        # get data from the packet
        data = self.packet[h_size:]

        self.sniffer.istcp = False
        self.sniffer.sudp = source_port
        self.sniffer.stcp = dest_port
        self.sniffer.payload = ''.join((c if (c in string.printable) else '.') for c in data)

        self.send_packet(self.user, self.sniffer)
