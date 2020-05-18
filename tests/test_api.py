#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/27 1:04 PM
# @Author  : w8ay
# @File    : test_api.py
import unittest
import socket
import time

from lib.api.dnslog import DnsLogApi


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_dnslog(self):
        dnslog = DnsLogApi()
        subdomain = dnslog.new_domain()
        print(subdomain)
        socket.gethostbyname("testapi." + subdomain)
        time.sleep(1.5)
        result = dnslog.check()
        print(result)
        self.assertTrue(len(result) > 0)
