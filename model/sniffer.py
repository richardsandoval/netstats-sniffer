class Sniffer(object):
    def __init__(self, istcp, smac, dmac, sip, dip, flags, protocol, length, sudp, dudp, stcp, dtcp, payload, version,
                 user, host):
        self.dmac = dmac
        self.sip = sip
        self.dip = dip
        self.flags = flags
        self.protocol = protocol
        self.length = length
        self.sudp = sudp
        self.dudp = dudp
        self.stcp = stcp
        self.dtcp = dtcp
        self.payload = payload
        self.smac = smac
        self.istcp = istcp
        self.version = version
        self.user = user
        self.host = host
