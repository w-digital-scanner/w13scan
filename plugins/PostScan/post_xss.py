#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/15 8:08 PM
# @Author  : w8ay
# @File    : post_xss.py

import copy
import random

import requests

from lib.const import ignoreParams, POST_HINT
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'POST插件 XSS简易注入'
    desc = '''目前支持POST方式的请求'''

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL

        post_hint = self.requests.post_hint
        post_data = self.requests.post_data

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        if method == 'POST':
            if post_hint == POST_HINT.NORMAL:
                rndStr = 9000 + random.randint(1, 999)
                payload = "<img/src=xyz OnErRor=alert(" + str(rndStr) + ")>"
                for k, v in post_data.items():
                    if k.lower() in ignoreParams:
                        continue
                    data = copy.deepcopy(post_data)
                    data[k] = v + payload
                    r = requests.post(url, headers=headers, data=data)
                    html = r.text
                    if payload in html:
                        out.success(url, self.name, payload="{}={}".format(k, data[k]), data=str(data),
                                    raw=r.raw)
