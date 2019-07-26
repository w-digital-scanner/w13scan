#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/17 4:34 PM
# @Author  : w8ay
# @File    : expression_language_injection.py

import copy
import os
import random
import re

import requests

from W13SCAN.lib.common import random_str
from W13SCAN.lib.const import acceptedExt, ignoreParams, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '服务端模板注入SSTI'
    desc = '''对GET请求参数进行相关测试'''
    level = Level.HIGHT

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
                data = copy.deepcopy(params)

                randint1 = random.randint(100, 900)
                randint2 = random.randint(100, 900)
                randstr = random_str(4)
                payloads = {
                    "{ranstr}${{{int1}*{int2}}}{ranstr}".format(ranstr=randstr, int1=randint1, int2=randint2),
                    "{ranstr}#{{{int1}*{int2}}}{ranstr}".format(ranstr=randstr, int1=randint1, int2=randint2)
                }
                flag = "{ranstr}.?{{?{int}}}?{ranstr}".format(ranstr=randstr, int=randint1 * randint2)

                for payload in payloads:
                    data[k] = v + payload
                    r = requests.get(netloc, params=data, headers=headers)
                    if re.search(flag, r.text):
                        out.success(url, self.name, payload="{}:{}".format(k, data[k], raw=r.raw))
