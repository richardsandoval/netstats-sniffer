import json
import urllib

from tornado import httpclient
from tornado.httputil import HTTPHeaders
from datetime import datetime as t

from model.data import Data


class SnifferClient(object):
    def __init__(self, user):
        self.user = user
        self.header = HTTPHeaders({
            'Content-Type': 'application/json',
            'Authorization': 'JWT {0}'.format(user.jwt)
        })
        self.http = httpclient.HTTPClient()
        self.opts = json.loads(open('config.json').read())

    def post_sniffer(self, sniffer):
        try:
            uri = "{0}/{1}/{2}".format(self.opts['url'],
                                       self.opts['prefix'],
                                       self.opts['sniffer'])

            req = self.http.fetch(uri, method='POST', body=json.dumps(sniffer.__dict__), headers=self.header)
            print req.body
            self.http.close()
        except httpclient.HTTPError as e:
            print e.message
            self.http.close()
        except Exception as e:
            print e.message
            self.http.close()

    def get_status(self):
        try:
            uri = "{0}/{1}/{2}/{3}".format(self.opts['url'],
                                           self.opts['prefix'],
                                           self.opts['status'],
                                           self.user.id)
            req = self.http.fetch(uri, method='GET', headers=self.header)
            response = json.loads(req.body)['data']
            dump = response['body']
            return dump['status']
        except httpclient.HTTPError as e:
            print e.message
            self.http.close()
            return e
        except Exception as e:
            print e.message
            self.http.close()
            return e

    def create_data(self):
        try:
            data = Data(None, t.now().isoformat(), None, self.user.id)
            uri = "{0}/{1}/{2}".format(self.opts['url'],
                                       self.opts['prefix'],
                                       self.opts['data'])
            body = urllib.urlencode(data)
            req = self.http.fetch(uri, method='POST', headers=self.header, body=body)
            response = json.loads(req.body)['data']
            dump = response['body']
            data.id = dump['id']
            return data
        except httpclient.HTTPError as e:
            print e.message
            self.http.close()
            return e
        except Exception as e:
            print e.message
            self.http.close()
            return e

    def end_data(self, data):
        try:
            data.endDate = t.now().isoformat()
            uri = "{0}/{1}/{2}/{3}".format(self.opts['url'],
                                           self.opts['prefix'],
                                           self.opts['data'],
                                           data.id)
            body = urllib.urlencode(data)
            self.http.fetch(uri, method='PUT', headers=self.header, body=body)
        except httpclient.HTTPError as e:
            print e.message
            self.http.close()
            return e
        except Exception as e:
            print e.message
            self.http.close()
            return e
