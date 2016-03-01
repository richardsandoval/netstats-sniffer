import threading

from analysis.reader import SnifferReader


class Worker(threading.Thread):
    def __init__(self, thread_num, user):
        threading.Thread.__init__(self)
        self.thread_num = thread_num
        self.signal = True
        self.user = user
        self.sniffer = SnifferReader(self.user)

    def run(self):
        while self.signal:
            self.run_loop()

    def run_loop(self):
        self.sniffer.start()
