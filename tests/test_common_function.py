#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 1:37 PM
# @Author  : w8ay
# @File    : test_get_parent_paths.py
import platform
import sys
import unittest
from urllib.parse import urlparse

import requests

from W13SCAN import VERSION
from W13SCAN.lib.common import get_parent_paths, get_links, createGithubIssue


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_get_parent_paths(self):
        url = "https://github.com/w-digital-scanner/w9scan/blob/master/plugins/spider_file/bcrpscan.py"
        p = urlparse(url)
        r = get_parent_paths(p.path, False)
        d = ['/w-digital-scanner/w9scan/blob/master/plugins/spider_file/',
             '/w-digital-scanner/w9scan/blob/master/plugins/', '/w-digital-scanner/w9scan/blob/master/',
             '/w-digital-scanner/w9scan/blob/', '/w-digital-scanner/w9scan/', '/w-digital-scanner/', '/']
        self.assertTrue(r == d)
        r = get_parent_paths(url, True)
        d2 = ['https://github.com/w-digital-scanner/w9scan/blob/master/plugins/spider_file/',
              'https://github.com/w-digital-scanner/w9scan/blob/master/plugins/',
              'https://github.com/w-digital-scanner/w9scan/blob/master/',
              'https://github.com/w-digital-scanner/w9scan/blob/', 'https://github.com/w-digital-scanner/w9scan/',
              'https://github.com/w-digital-scanner/', 'https://github.com/']
        self.assertTrue(r == d2)

    def test_get_links(self):
        domain = "https://x.hacking8.com"
        r = requests.get(domain)
        links = get_links(r.text, domain)
        self.assertTrue(len(links) > 0)

    def test_createGithubIssue(self):
        errMsg = "W13scan baseproxy get request traceback:\n"
        errMsg += "Running version: {}\n".format(VERSION)
        errMsg += "Python version: {}\n".format(sys.version.split()[0])
        errMsg += "Operating system: {}\n".format(platform.platform())
        errMsg += "Threads: {}".format(51)
        excMsg = '''
Traceback (most recent call last):
  File "/W13SCAN/lib/plugins.py", line 51, in execute
    output = self.audit()
  File "/W13SCAN/plugins/PerFile/analyze_parameter.py", line 60, in audit
    raise Exception("test exception 111")
Exception: test exception
        '''.strip()
        if createGithubIssue(errMsg, excMsg):
            self.assertTrue(1)
        else:
            self.assertTrue(False)
