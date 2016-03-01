class User(object):
    def __init__(self, id, username, jwt, sniffer, status):
        self.id = id
        self.username = username
        self.jwt = jwt
        self.sniffer = sniffer
        self.status = status