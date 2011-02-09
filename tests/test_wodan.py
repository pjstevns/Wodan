#!/usr/bin/python

import httplib
import unittest

CACHED = ('wodan',80)
DIRECT = ('wodan',8080)

"""
setup:

    VirtualHost 
    DocumentRoot symlink to src/wodan/tests/docs
    ErrorDocument 404 /error.html
    ErrorDocument 502 /error.html
    ErrorDocument 503 /error.html

"""

class testWodan(unittest.TestCase):
    def setUp(self):
        self.cached = httplib.HTTPConnection(*CACHED)
        self.direct = httplib.HTTPConnection(*DIRECT)

    def test_Connections(self):
        self.failUnless(self.cached)
        self.failUnless(self.direct)
        self.failUnless(self.cached != self.direct)

    def test_HTTP_OK(self):
        self.cached.request('GET','/')
        self.direct.request('GET','/')
        r1 = self.cached.getresponse()
        r2 = self.direct.getresponse()
        self.failUnless(r1.status == 200 and r1.reason == 'OK')
        self.failUnless(r2.status == 200 and r2.reason == 'OK')
        d1 = r1.read()
        d2 = r2.read()
        self.failUnless(d1 == '200 OK:wodan-test\n')
        self.failUnless(d2 == '200 OK:wodan-test\n')

    def test_HTTP_NOT_FOUND(self):
        self.cached.request('GET','/missing.doc.html')
        self.direct.request('GET','/missing.doc.html')
        r1 = self.cached.getresponse()
        r2 = self.direct.getresponse()
        self.failUnless(r1.status == 404 and r1.reason == 'Not Found')
        self.failUnless(r2.status == 404 and r2.reason == 'Not Found')

if __name__=='__main__':
    unittest.main()
