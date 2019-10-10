#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/27 1:04 PM
# @Author  : w8ay
# @File    : test_api.py
import unittest

from W13SCAN.api import Scanner


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_api_get(self):
        self.scanner = Scanner(threads=10)
        self.scanner.put("http://emlog6.demo/?post=1")
        self.scanner.run()

    def test_http_smuggling(self):
        url = "https://acfe1f111e6d561480049808007c0038.web-security-academy.net/"
        scan = Scanner(include_plugins=['http_smuggling.py'])
        scan.put(url)
        scan.run()
