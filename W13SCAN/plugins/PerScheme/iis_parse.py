#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/20 8:49 PM
# @Author  : w8ay
# @File    : iis_parse.py

import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'iis解析漏洞'
    desc = '''iis 7.5 parse'''
    level = Level.MIDDLE

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

        if self.response.language == "PHP" or self.response.language is None:
            domain = "{}://{}/".format(p.scheme, p.netloc)
            payload = domain + "robots.txt/.php"
            r = requests.get(payload, headers=headers)
            if "user-agent" in r.text.lower() and 'text/plain' not in r.headers.get("Content-Type", ''):
                out.success(payload, self.name)
