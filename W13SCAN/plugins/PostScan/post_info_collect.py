#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/8/24 10:42 PM
# @Author  : w8ay
# @File    : post_info_collect.py
import re

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'POST敏感信息收集插件'
    desc = '''从POST返回的网页中获取敏感信息'''
    level = Level.LOW

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
            # 手机号
            regx_phone = r'(?:139|138|137|136|135|134|147|150|151|152|157|158|159|178|182|183|184|187|188|198|130|131|132|155|156|166|185|186|145|175|176|133|153|177|173|180|181|189|199|170|171)[0-9]{8}'
            # 身份证
            regx_identify = r'([1-9]\d{5}[12]\d{3}(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])\d{3}[0-9xX])'
            for _ in [regx_phone, regx_identify]:
                texts = re.findall(_, resp_str, re.M | re.I)
                if texts:
                    for i in set(texts):
                        if out.set(i):
                            out.success(url, self.name, method='POST', info=i)
