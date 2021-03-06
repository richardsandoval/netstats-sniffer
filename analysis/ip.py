from struct import unpack

from analysis.icmp import ICMP
from analysis.tcp import TCP
from analysis.udp import UDP


class IP(object):
    def __init__(self, eth_length, sniffer, packet, socket, user):
        self.user = user
        self.eth_length = eth_length
        self.sniffer = sniffer
        self.packet = packet
        self.socket = socket

    def send_ip_packet(self):
        ip_header = self.packet[self.eth_length:20 + self.eth_length]
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = self.socket.inet_ntoa(iph[8])
        d_addr = self.socket.inet_ntoa(iph[9])

        self.sniffer.length = 1500 - len(self.packet)
        self.sniffer.version = version
        self.sniffer.protocol = protocol
        self.sniffer.sip = s_addr
        self.sniffer.dip = d_addr
        t = iph_length + self.eth_length

        if protocol == 6:
            tcp = TCP(t, self.sniffer, self.packet, self.socket, self.user)
            tcp.send_tcp_packet()
        elif protocol == 1:
            icmp = ICMP(t, self.sniffer, self.packet, self.user)
            icmp.send_icmp_packet()
        elif protocol == 17:
            udp = UDP(t, self.sniffer, self.packet, self.user)
            udp.send_udp_packet()
