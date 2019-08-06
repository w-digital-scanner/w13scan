#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/8/6 4:39 PM
# @Author  : w8ay
# @File    : cookie.py
import copy

import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Cookie控制的值在页面上显示'
    desc = '''暂只支持Get请求方式'''
    level = Level.LOW

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
        cookies = self.requests.cookies

        if method == 'GET':
            if p.query == '':
                return
            if not cookies or len(cookies) == 0:
                return

            for k, v in cookies.items():
                if v.lower() not in resp_str.lower():
                    continue
                payload = "[<{}>]2333_w13scan"
                data = copy.deepcopy(cookies)
                data[k] = v + payload
                r = requests.get(url, cookies=data, headers=headers)
                if payload in r.text:
                    out.success(url, self.name, cookie="{}:{}".format(k, data[k]), raw=r.raw)
