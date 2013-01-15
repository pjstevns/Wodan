#!/usr/bin/python

import httplib
import unittest

CACHED = ('wodan', 80)
DIRECT = ('wodan', 8880)

"""
setup:

    edit and include the wodan.conf in this directory in
    your apache setup

"""


def request(type, method, path, body=None, headers=None):
    if not headers:
        headers = {}
    assert(type in (CACHED, DIRECT))
    connection = httplib.HTTPConnection(*type)
    connection.request(method, path, body, headers)
    r = connection.getresponse()
    d = r.read()
    return (r, d)


class testWodan(unittest.TestCase):
    def setUp(self):
        self.cached = CACHED
        self.direct = DIRECT

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


if __name__ == '__main__':
    unittest.main()
