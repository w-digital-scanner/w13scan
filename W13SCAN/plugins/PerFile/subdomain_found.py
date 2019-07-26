#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/16 5:53 PM
# @Author  : w8ay
# @File    : subdomain_found.py
from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase
import re


class W13SCAN(PluginBase):
    name = '子域名搜集'
    desc = '''从返回包中搜集子域名'''
    level = Level.LOW

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL
        data = self.requests.get_body_data().decode(self.response.decoding or 'utf-8')

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        if self.requests.tld:
            _ = '(?:[a-zA-Z0-9]+\.)+' + self.requests.tld.replace('.', r'\.')
            texts = re.findall(_, resp_str, re.M | re.I)
            if texts:
                for i in set(texts):
                    if out.set(i):
                        out.success(url, self.name, info=i)
