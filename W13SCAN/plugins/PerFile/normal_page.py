#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/11 4:51 PM
# @Author  : w8ay
# @File    : normal_page.py
import re

from W13SCAN.lib.const import Level
from W13SCAN.lib.helper.phpinfo_helper import get_phpinfo
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '通用敏感信息搜集'
    desc = '''只从返回包中搜集通用的敏感信息'''
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

        # phpinfo
        if "<title>phpinfo()</title>" in resp_str:
            info = get_phpinfo(resp_str)
            out.success(url, self.name, info=info)

        # 手机号
        regx_phone = r'(?:139|138|137|136|135|134|147|150|151|152|157|158|159|178|182|183|184|187|188|198|130|131|132|155|156|166|185|186|145|175|176|133|153|177|173|180|181|189|199|170|171)[0-9]{8}'
        # 身份证
        regx_identify = r'([1-9]\d{5}[12]\d{3}(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])\d{3}[0-9xX])'
        for _ in [regx_phone, regx_identify]:
            texts = re.findall(_, resp_str, re.M | re.I)
            if texts:
                for i in set(texts):
                    if out.set(i):
                        out.success(url, self.name, info=i)
