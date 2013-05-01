#!/usr/bin/python

import httplib
import unittest
import BaseHTTPServer
import time
import thread
import random

CACHED = ('wodan', 80)
DIRECT = ('wodan', 8880)

SLOW_SERVER = ('wodan', 8123)
SLOW_SERVER_DELAY = 3

SLOW_FRONT = ('wodan', 8888)

"""
setup:

    edit and include the wodan.conf in this directory in
    your apache setup

"""


class requestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def log_request(self, *args):
        pass

    def do_GET(self, *args):
        time.sleep(SLOW_SERVER_DELAY)
        self.send_response(200, 'OK')
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write('wodan -- slow response\n\n')
        self.wfile.flush()
        return


def runSlowServer():

    def start_server(*args):
        httpd = BaseHTTPServer.HTTPServer(SLOW_SERVER, requestHandler)
        httpd.serve_forever()

    thread.start_new_thread(start_server, ())


def request(type, method, path, body=None, headers=None):
    if not headers:
        headers = {}
    assert(type in (CACHED, DIRECT, SLOW_FRONT, SLOW_SERVER))
    connection = httplib.HTTPConnection(*type)
    connection.request(method, path, body, headers)
    r = connection.getresponse()
    d = r.read()
    return (r, d)


class testWodan(unittest.TestCase):
    def setUp(self):
        self.cached = CACHED
        self.direct = DIRECT
        self.slow_back = SLOW_SERVER
        self.slow_front = SLOW_FRONT

    def test_Connections(self):
        cached = httplib.HTTPConnection(*CACHED)
        direct = httplib.HTTPConnection(*DIRECT)
        self.failUnless(cached)
        self.failUnless(direct)
        self.failUnless(cached != direct)

    def test_HTTP_OK(self):
        (r1, d1) = request(self.cached, 'GET', '/')
        (r2, d2) = request(self.direct, 'GET', '/')
        self.failUnless(r1.status == 200 and r1.reason == 'OK')
        self.failUnless(r2.status == 200 and r2.reason == 'OK')
        self.failUnless(d1 == '200 OK:wodan-test\n', d1)
        self.failUnless(d2 == '200 OK:wodan-test\n')

    def test_HTTP_NOT_FOUND(self):
        (r1, d1) = request(self.cached, 'GET', '/missing.doc.html')
        (r2, d2) = request(self.direct, 'GET', '/missing.doc.html')
        self.failUnless(r1.status == 404 and r1.reason == 'Not Found')
        self.failUnless(r2.status == 404 and r2.reason == 'Not Found')
        self.failUnless(d1 == '404 Not Found:wodan-test direct\n')
        self.failUnless(d2 == '404 Not Found:wodan-test direct\n')

    def test_HTTP_BAD_GATEWAY_cached(self):
        (r1, d1) = request(self.cached, 'GET', '/fail/index.html')
        self.failUnless(r1.status == 200 and r1.reason == 'OK')
        self.failUnless(d1 == '404 Not Found:wodan-test cached\n', d1)

    def test_HTTP_BAD_GATEWAY_direct(self):
        (r2, d2) = request(self.direct, 'GET', '/fail/index.html')
        self.failUnless(r2.status == 404 and r2.reason == 'Not Found')
        self.failUnless(d2 == '404 Not Found:wodan-test direct\n', d2)

    def test_HTTP_NOT_MODIFIED(self):
        (r1, d1) = request(self.direct, 'GET', '/')
        (r2, d2) = request(self.cached, 'GET', '/')
        mtime = r1.getheader('Last-Modified').strip()
        (r1, d1) = request(self.direct, 'GET', '/',
                           headers={'If-Modified-Since': mtime})
        (r2, d2) = request(self.cached, 'GET', '/',
                           headers={'If-Modified-Since': mtime})
        self.failUnless(r1.status == 304)
        self.failUnless(r2.status == 304, "expect [304] got [%d]" % r2.status)

    def test_timeout(self):
        url = '/slow/%s/index.html' % random.random()
        (r1, d1) = request(self.cached, 'GET', url)
        self.failUnless(r1.status == 504)
        (r2, d2) = request(self.slow_back, 'GET', url)
        self.failUnless(r2.status == 200, r2.status)
        (r3, d3) = request(self.slow_front, 'GET', url)
        self.failUnless(r3.status == 200, r3.status)
        (r4, d4) = request(self.cached, 'GET', url)
        self.failUnless(r4.status == 200)

if __name__ == '__main__':
    runSlowServer()
    raw_input("Hit ENTER to continue")
    unittest.main()
