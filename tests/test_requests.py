#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/8/28 5:47 PM
# @Author  : w8ay
# @File    : test_requests.py
import unittest

import requests

from W13SCAN.api import Scanner


class TestCase(unittest.TestCase):
    def setUp(self):
        self.scanner = Scanner(threads=10)

    def tearDown(self):
        pass

    def test_requests(self):
        url = "http://m.weather.com.cn"
        headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "accept-encoding": "gzip, deflate",
            "connection": "keep-alive",
            "upgrade-insecure-requests": "1"
        }
        r = requests.get(url, headers=headers)
        self.assertTrue(r.status_code == 200)


if __name__ == '__main__':
    unittest.main()
