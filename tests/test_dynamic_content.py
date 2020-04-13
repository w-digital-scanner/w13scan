#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/12 9:22 PM
# @Author  : w8ay
# @File    : test_dynamic_content.py

import unittest

from lib.helper.diifpage import findDynamicContent


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_diff_page_radio(self):
        # url1 = "https://x.hacking8.com/post-348.html"
        # url2 = "https://x.hacking8.com/post-342-1.html"
        # html1 = getFilteredPageContent(requests.get(url1).text)
        # html2 = getFilteredPageContent(requests.get(url2).text)
        # print(html1, html2)
        html1 = "helaaaaaaaaaaaaaaaaaaalo this is bookaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        html2 = "hellaaaaaaaaaaaaaaaaaaaaaaaao this is desktopccccccccccccccccccccccc"
        print(findDynamicContent(html1, html2))
