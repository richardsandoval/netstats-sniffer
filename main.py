import time

from http.client import SnifferClient
from http.login import Login
from model.user import User
from worker.worker import Worker

user = User(None, None, None, None, None)
login = Login(user)
login.login()
sniffer = SnifferClient(user)
started = False
w_sniffer = Worker(1, user)
while True:
    time.sleep(5)
    if sniffer.get_status():
        if not started:
            w_sniffer.signal = True
            w_sniffer.start()
        started = True
    else:
        started = False
        w_sniffer.signal = False
        login = Login(user)
        login.login()
        sniffer = SnifferClient(user)
        w_sniffer = Worker(1, user)
