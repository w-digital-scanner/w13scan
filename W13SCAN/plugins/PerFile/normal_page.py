#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/11 4:51 PM
# @Author  : w8ay
# @File    : normal_page.py

from W13SCAN.lib.const import Level
from W13SCAN.lib.helper.phpinfo_helper import get_phpinfo
from W13SCAN.lib.helper.sensitive_info import sensitive_idcard, sensitive_bankcard
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

        for func in [sensitive_idcard, sensitive_bankcard]:
            rets = func(resp_str)
            if rets:
                for ret in rets:
                    content = ret["content"]
                    if out.set(content):
                        out.success(url, self.name, content=content, type=ret["type"])
