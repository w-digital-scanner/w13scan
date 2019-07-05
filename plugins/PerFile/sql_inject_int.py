#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 10:56 AM
# @Author  : w8ay
# @File    : sql_inject_int.py
import copy
import os
import random
import re
from urllib.parse import urlparse

import requests

from lib.common import prepare_url
from lib.const import acceptedExt, ignoreParams
from lib.data import Share
from lib.helper.diifpage import fuzzy_equal
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '数字型SQL注入'
    desc = '''目前仅支持GET方式的请求'''

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        if method == 'GET':
            if p.query == '':
                return
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return

            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                if not re.search('^-?\d+(\.\d+)?$', v):
                    continue
                data = copy.deepcopy(params)
                # 判断条件:
                # 1. -randint !== origin
                # 2. +randint-randint == origin
                payload1 = "{0}+{1}".format(v, random.randint(10, 100))
                data[k] = payload1
                url1 = prepare_url(netloc, params=data)
                r = requests.get(url1, headers=headers)
                html1 = r.text
                if fuzzy_equal(resp_str, html1, 0.97):
                    continue
                payload2 = "{0}+{1}-{1}".format(v, random.randint(10, 100))
                data[k] = payload2
                r2 = requests.get(netloc, params=data, headers=headers)
                html2 = r2.text
                if fuzzy_equal(resp_str, html2, 0.8):
                    msg = " {k}:{v} !== {k}:{v1} and {k}:{v} === {k}:{v2}".format(k=k, v=v, v1=payload1,
                                                                                  v2=payload2)
                    out.success(url, self.name, payload=k, condition=msg)
                    break
