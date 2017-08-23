#!/usr/bin/env python
import SimpleHTTPServer
import SocketServer
import sys
import urllib
import logging
from optparse import OptionParser


class ResultsProvider(object):
    '''Base class used to fetch data from server for forwarding'''

    import requests
    import socket
    import time

    def __init__(self, **kwargs):
        '''Constructor with sensible requests defaults'''
        self.session = self.requests.Session()
        self.wait = kwargs.get('wait', 2.0)
        self.session.verify = kwargs.get('verify', False)
        self.session.timeout = kwargs.get('timeout', 5)
        self.session.stream = kwargs.get('stream', False)
        self.session.proxies = kwargs.get('proxies', {})
        self.session.headers = kwargs.get('headers', {})
        self.session.allow_redirects = kwargs.get('allow_redirects', True)
        self.session.cookies = self.requests.utils.cookiejar_from_dict(kwargs.get('cookies', {}))
        self.url = kwargs.get('url', None)



    def doRequest(self, verb, url, **kwargs):
        '''Makes web request with timeoout support using requests session'''
        while 1:
            try:
                body = kwargs.pop('body') if kwargs.has_key('body') else None
                rargs = {}
                for a in ['data', 'json', 'params', 'headers']:
                    if kwargs.has_key(a):
                        rargs[a] = kwargs.pop(a)
                req = self.requests.Request(verb, url, **rargs) # data, headers, params, json
                prepped = req.prepare()
                if body:
                    prepped.body = body
                response = self.session.send(prepped, **kwargs) # other params here
                break
            except (self.socket.error, self.requests.exceptions.RequestException):
                logging.exception('Retrying request in %.2f seconds...', self.wait)
                self.time.sleep(self.wait)
                continue
        return response




    def nextResult(self):
        '''Redefine me to make the request and return the response.text'''
        #return self.doRequest(url='http://site/whatever/' + str(calculated_value)).text
        raise NotImplementedError





class ResultsProviderImpl(ResultsProvider):
    '''Implementation for forwarding arbitrary requests to another server'''

    def __init__(self, **kwargs):
        super(ResultsProviderImpl, self).__init__(**kwargs)
        self.hostname=kwargs.get('hostname')
        self.protocol=kwargs.get('protocol', 'http')
        self.port=kwargs.get('port')


    def nextResult(self, verb, path, **kwargs):
        r = self.doRequest(verb, '%s://%s:%s%s' %(self.protocol, self.hostname, self.port, path), **kwargs)
        return r




class ThreadedTCPServer(SocketServer.ThreadingTCPServer):
    '''Simple Threaded TCP server'''
    pass


class ServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    '''Simple http server request handler'''
    import datetime
    counter=0

    skip_headers = ['content-length', 'transfer-encoding', 'content-encoding', 'connection']

    def print_debug(self, title, data):
        sep = '=' * 40 + '\n'
        dt = self.datetime.datetime.now()
        dts = dt.strftime('%d/%m/%Y %H:%M:%S')
        self.counter+=1
        print sep + title + ' - ' + str(self.counter) + ' - ' + dts + '\n' + sep + data + '\n'


    def send_response(self, code, message=None):
        '''Redefine from original to get rid of extra headers'''
        self.log_request(code)
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("%s %d %s\r\n" %
                             (self.protocol_version, code, message))
            # print (self.protocol_version, code, message)
        #self.send_header('Server', self.version_string())
        #self.send_header('Date', self.date_time_string())



    def do(self, verb, data=None):
        args = {'headers' : self.headers.dict}
        if data:
            args['data'] = data
        response = self.server.resultsProvider.nextResult(verb, self.path, **args)
        if self.server.debug:
            self.print_debug('HTTP Request Received', self.raw_requestline + str(self.headers) + '\r\n' + (data if data else ''))

        self.send_response(response.status_code, response.reason)
        for header in response.headers.iteritems():
            if  header[0].lower() not in self.skip_headers:
                #self.print_debug('Header Sent', ' :'.join([header[0], header[1]]))
                self.send_header(header[0], header[1])
        self.send_header('Content-Length', int(len(response.content)))
        self.send_header('Connection', 'close')
        self.wfile.write('\r\n')
        self.wfile.write(response.content)
        if self.server.debug:
            http_version = '.'.join([a for a in str(response.raw.version)])
            version_line = 'HTTP/%s %s %s' %(http_version, response.status_code, response.reason)
            headers = '\r\n'.join([ '%s : %s' %(a[0],a[1]) for a in response.headers.items()])
            self.print_debug('HTTP Response Received', '\r\n'.join([version_line, headers, '\r\n' + response.content]))
            #self.print_debug('Length of response', str(int(len(response.content))))

        self.wfile.flush()
        self.wfile.close()


    def do_GET(self):
        self.do('GET')


    def do_HEAD(self):
        self.do('HEAD')


    def do_POST(self):
        data = self.rfile.read(int(self.headers['Content-Length'])) if \
            self.headers.has_key('Content-Length') else ''
        self.do('POST', data=data)


def match_url(input):
    return ((input.startswith('http://') or input.startswith('https://')) and \
        input.endswith('/') and len(input.split('/')[2]) > 4 and len(input.split('/')) == 4)


if __name__ == '__main__':
    parser = OptionParser(usage='%prog -u [url] [options]')
    parser.add_option('-d', '--debug', dest='debug', action='store_true', help='show debugging messages')
    parser.add_option('-u', '--url', dest='remoteurl', type='string', help='remote base url')
    parser.add_option('-p', '--port', dest='port', type='int', default=8000, help='local listen port')
    parser.add_option('-a', '--address', dest='address', type='string', default='0.0.0.0', help='local listen address')
    parser.add_option('-x', '--proxy', dest='proxy', type='string', help='optional proxy to use in format http://address:port/')
    opts, args = parser.parse_args()


    if opts.remoteurl == None:
        print 'Please provide a remote url using the -u --url option'
        sys.exit()
    elif not match_url(opts.remoteurl):
        print 'Please enter remote url in format protocol://host[:port]/'
        sys.exit()

    try:
        [protocol, _, host_port, _] = opts.remoteurl.split('/')
        protocol = protocol.rstrip(':')
        hostparts = host_port.split(':')
        hostname = hostparts[0]
        rport = int(hostparts[1]) if len(hostparts) > 1 else {'http' : 80, 'https' : 443}[protocol]
    except:
        print 'Please enter remote url in format protocol://host[:port]/'
        sys.exit()

    if opts.proxy:
        if not match_url(opts.proxy) and not opts.proxy.startswith('https'):
            print 'Please enter proxy in format http://host:port/'
            sys.exit()
        if opts.debug:
            print 'Using proxy ' + opts.proxy
        proxies = {protocol : opts.proxy}
    else:
        proxies = {}


    httpd = ThreadedTCPServer((opts.address, opts.port), ServerHandler)
    httpd.debug = opts.debug or False

    # add the custom resultsprovider implementation
    httpd.resultsProvider = ResultsProviderImpl(hostname=hostname, protocol=protocol, port=rport, proxies=proxies)


    print "Serving at: http://%s:%s/, forwarding requests to %s" % (opts.address, str(opts.port), opts.remoteurl)
    httpd.serve_forever()
