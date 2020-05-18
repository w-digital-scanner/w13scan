#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/6 1:48 PM
# @Author  : w8ay
# @File    : test_resver_api.py
import threading
import unittest

import requests

from lib.api.reverse_api import reverseApi
from lib.reverse.reverse_http import http_start


class TestCase(unittest.TestCase):
    def setUp(self):
        thread = threading.Thread(target=http_start)
        thread.setDaemon(True)
        thread.start()

        self.reverse = reverseApi()

    def tearDown(self):
        pass

    def test_http(self):
        httplog = self.reverse.generate_http_token()
        fullname = httplog["fullname"]
        token = httplog["token"]
        requests.get(fullname)
        self.assertTrue(len(self.reverse.check(token)) > 0)

    def test_show_all(self):
        for i in range(10):
            httplog = self.reverse.generate_http_token()
            fullname = httplog["fullname"]
            requests.get(fullname)
        all = self.reverse.show_all()
        self.assertTrue(len(all) >= 10)
