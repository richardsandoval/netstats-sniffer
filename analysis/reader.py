import socket, sys
from struct import *

from analysis.ip import IP
from model.sniffer import Sniffer


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


class SnifferReader(object):
    def __init__(self, user):
        try:
            self.user = user
            self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        except socket.error:
            sys.exit()

    def start(self):
        packet = self.s.recvfrom(65565)

        # packet string from tuple
        packet = packet[0]

        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])

        sniffer = Sniffer(None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                          self.user.id, None)
        sniffer.dmac = eth_addr(packet[0:6])
        sniffer.smac = eth_addr(packet[6:12])
        sniffer.protocol = str(eth_protocol)

        if eth_protocol == 8:
            IP(eth_length, sniffer, packet, socket, self.user).send_ip_packet()
