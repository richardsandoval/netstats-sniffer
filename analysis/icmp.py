import string
from struct import unpack

from analysis.packet import AbstractPacket


class ICMP(AbstractPacket):
    def __init__(self, t, sniffer, packet, user):
        self.t = t
        self.sniffer = sniffer
        self.packet = packet
        self.user = user

    def send_icmp_packet(self):
        icmph_length = 4
        icmp_header = self.packet[self.t: self.t + 4]

        icmph = unpack('!BBH', icmp_header)
        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]

        h_size = self.t + icmph_length
        data_size = len(self.packet) - h_size

        # get data from the packet
        data = self.packet[h_size:]
        self.sniffer.istcp = True
        self.sniffer.payload = ''.join((c if (c in string.printable) else '.') for c in data)

        self.send_packet(self.user, self.sniffer)
