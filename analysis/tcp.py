import string
from struct import unpack

from analysis.packet import AbstractPacket


class TCP(AbstractPacket):
    def __init__(self, t, sniffer, packet, socket, user):
        self.user = user
        self.t = t
        self.sniffer = sniffer
        self.packet = packet
        self.socket = socket

    def send_tcp_packet(self):
        tcp_header = self.packet[self.t:self.t + 20]

        tcph = unpack('!HHLLBBHHH', tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        h_size = self.t + tcph_length * 4
        data = self.packet[h_size:]

        self.sniffer.istcp = True
        self.sniffer.stcp = source_port
        self.sniffer.dtcp = dest_port
        self.sniffer.payload = ''.join((c if (c in string.printable) else '.') for c in data)
        self.sniffer.host = self._getdnsbyip(self.sniffer.dip)
        self.send_packet(self.user, self.sniffer)

    def _getdnsbyip(self, ip):
        try:
            if ip.find('127.0.0.') == -1:
                ret = self.socket.gethostbyaddr(ip)
                name = ret[0].split('.')
                if name[len(name) - 2].find('localhost') == -1:
                    join = (name[len(name) - 2], name[len(name) - 1])
                    return '.'.join(join)
            return None
        except self.socket.herror:
            return None
