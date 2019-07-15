#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/15 3:52 PM
# @Author  : w8ay
# @File    : xss.py

import copy
import os
import random

import requests

from lib.common import random_str
from lib.const import acceptedExt, ignoreParams
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'XSS简易探测'
    desc = '''暂只支持Get请求方式'''

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

            rndStr = 9000 + random.randint(1, 999)
            tag = random_str(4)
            payload = "<{tag}>{randint}</{tag}>".format(tag=tag, randint=rndStr)

            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                data = copy.deepcopy(params)
                data[k] = v + payload
                r = requests.get(url, headers=headers, params=data)
                html1 = r.text
                if payload in html1:
                    out.success(url, self.name, payload="{}:{}".format(k, data[k]), raw=r.raw, descript="探测tag被解析")
                    break
