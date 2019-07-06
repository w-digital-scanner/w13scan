#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 4:45 PM
# @Author  : w8ay
# @File    : jsonp.py

import copy
import os
import random
import re

import requests

from lib.common import prepare_url
from lib.const import acceptedExt, ignoreParams
from lib.helper.diifpage import GetRatio
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'JSONP寻找插件'
    desc = '''自动寻找JSONP请求并自动去除referer查看能否利用'''

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL
        data = self.requests.get_body_data().decode()

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        combine = '^\S+\(\{.*\}\)'

        if re.match(combine, resp_str, re.I | re.S):
            if "Referer" in headers:
                del headers["Referer"]
            if method == 'GET':
                r = requests.get(url, headers=headers)
                if GetRatio(resp_str, r.text) >= 0.8:
                    out.success(url, self.name)
            elif method == 'POST':
                r = requests.post(url, headers=headers, data=data)
                if GetRatio(resp_str, r.text) >= 0.8:
                    out.success(url, self.name, payload=str(data))
