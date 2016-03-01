from abc import ABCMeta, abstractmethod

from http.client import SnifferClient


class AbstractPacket(object):
    __metaclass__ = ABCMeta

    def send_packet(self, user, sniffer):
        client = SnifferClient(user)
        client.post_sniffer(sniffer)
