#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/12/12 3:19 PM
# @Author  : w8ay
# @File    : test_sensitive_info.py
import unittest

from lib.helper.helper_sensitive import *


class TestCase(unittest.TestCase):
    def setUp(self):
        self.html = '''
        <body>
        <table>
        <td>bankcard</td><td>6223023941067993</td>
        <td>bankcard2</td><td>8880003996339638</td>
        <td>bankcard3</td><td>4720680298336447</td>
        <td>idcard</td><td>120221200101010459</td>
        <td>idcard2</td><td>120221200101012470</td>
        <td>idcard3</td><td>120221200101010651</td>
        <td>phone</td><td>13048825495</td>
        <td>email</td><td>aaaaaatest@aa.com</td>
        <td>email</td><td>aaaaaa.test@aa.com</td>
        </table>
        </body>
        '''

    def tearDown(self):
        pass

    def test_sensitive_bankcard(self):
        ret = sensitive_bankcard(self.html)
        print(ret)
        return self.assertTrue(len(ret) > 0)

    def test_sensitive_idcard(self):
        ret = sensitive_idcard(self.html)
        print(ret)
        return self.assertTrue(len(ret) > 0)

    def test_sensitive_phone(self):
        ret = sensitive_phone(self.html)
        print(ret)
        return self.assertTrue(len(ret) > 0)

    def test_sensitive_email(self):
        ret = sensitive_email(self.html)
        print(ret)
        return self.assertTrue(len(ret) > 0)
