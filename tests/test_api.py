#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/27 1:04 PM
# @Author  : w8ay
# @File    : test_api.py
import unittest

from W13SCAN.api import Scanner


class TestCase(unittest.TestCase):
    def setUp(self):
        self.scanner = Scanner(threads=10)

    def tearDown(self):
        pass

    def test_api_get(self):
        self.scanner.put("http://emlog6.demo/?post=1")
        self.scanner.run()
