#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/5 7:35 PM
# @Author  : w8ay
# @File    : api.py
import string
import time
from json import JSONDecodeError

import requests

from config import REVERSE_SLEEP
from lib.core.common import random_str


class DnsLogApi(object):

    def __init__(self):
        self.req = requests.Session()
        self._new_api = "http://www.dnslog.cn/getdomain.php?t=0." + random_str(10, string.digits)
        self._check_api = "http://www.dnslog.cn/getrecords.php?t=0." + random_str(10, string.digits)
        self.sleep = REVERSE_SLEEP

    def new_domain(self) -> str:
        '''
        返回dns域名
        :return:
        '''
        try:
            resp = self.req.get(self._new_api).text
        except:
            resp = ''
        return resp

    def check(self) -> list:
        time.sleep(self.sleep)
        try:
            resp = self.req.get(self._check_api).json()
        except JSONDecodeError:
            resp = []
        return list(resp)
