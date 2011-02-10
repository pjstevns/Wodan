#!/usr/bin/python

import httplib
import unittest

CACHED = ('wodan',80)
DIRECT = ('wodan',8080)

"""
setup:

    edit and include the wodan.conf in this directory in
    your apache setup

"""

def request(connection, method, path):
    connection.request(method, path)
    r = connection.getresponse()
    d = r.read()
    return (r,d)

class testWodan(unittest.TestCase):
    def setUp(self):
        self.cached = httplib.HTTPConnection(*CACHED)
        self.direct = httplib.HTTPConnection(*DIRECT)

    def test_Connections(self):
        self.failUnless(self.cached)
        self.failUnless(self.direct)
        self.failUnless(self.cached != self.direct)

    def test_HTTP_OK(self):
        (r1,d1) = request(self.cached, 'GET', '/')
        (r2,d2) = request(self.direct, 'GET', '/')
        self.failUnless(r1.status == 200 and r1.reason == 'OK')
        self.failUnless(r2.status == 200 and r2.reason == 'OK')
        self.failUnless(d1 == '200 OK:wodan-test\n')
        self.failUnless(d2 == '200 OK:wodan-test\n')

    def test_HTTP_NOT_FOUND(self):
        (r1,d1) = request(self.cached,'GET','/missing.doc.html')
        (r2,d2) = request(self.direct,'GET','/missing.doc.html')
        self.failUnless(r1.status == 404 and r1.reason == 'Not Found')
        self.failUnless(r2.status == 404 and r2.reason == 'Not Found')
        self.failUnless(d1 == '404 Not Found:wodan-test direct\n')
        self.failUnless(d2 == '404 Not Found:wodan-test direct\n')

    def test_HTTP_BAD_GATEWAY(self):
        (r1,d1) = request(self.cached, 'GET', '/fail/index.html')
        (r2,d2) = request(self.direct, 'GET', '/fail/index.html')
        self.failUnless(r1.status == 200 and r1.reason == 'OK')
        self.failUnless(d1 == '404 Not Found:wodan-test cached\n')
        self.failUnless(r2.status == 404 and r2.reason == 'Not Found')
        self.failUnless(d2 == '404 Not Found:wodan-test direct\n')


if __name__=='__main__':
    unittest.main()
