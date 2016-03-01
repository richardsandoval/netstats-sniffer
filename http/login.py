import json
import urllib

from tornado import httpclient


class Login(object):
    def __init__(self, user):
        self.user = user

    def login(self):
        http = httpclient.HTTPClient()
        try:
            opts = json.loads(open('config.json').read())
            uri = "{0}/{1}/{2}".format(opts['url'], opts['prefix'], opts['signin'])
            t_user = opts['credentials']
            body = urllib.urlencode(t_user)
            req = http.fetch(uri, method='POST', body=body, headers=None)
            response = json.loads(req.body)['data']
            dump = response['body']
            self.user.jwt = response['token']
            self.user.id = dump['id']
            self.user.username = dump['username']
            self.user.status = dump['status']
            self.user.data = dump['sniffer']
            http.close()
        except httpclient.HTTPError as e:
            print e.message
            http.close()
        except Exception as e:
            print e.message
            http.close()
