#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 12:01 PM
# @Author  : w8ay
# @File    : test_diffpage_radio.py
import unittest

import requests

from lib.helper.diifpage import GetRatio, fuzzy_equal


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_diff_page_radio(self):
        url1 = "https://x.hacking8.com/post-348.html"
        url2 = "https://x.hacking8.com/post-342.html"
        html1 = requests.get(url1).text
        html2 = requests.get(url2).text
        radio = GetRatio(html1, html2)
        print(radio)

    def test_fuzzy_equal(self):
        url1 = "http://emlog6.demo/?post=1"
        url2 = "http://emlog6.demo/?post=2"
        html1 = requests.get(url1).text
        html2 = requests.get(url2).text
        print(fuzzy_equal(html1, html2))
