#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/8/8 3:48 PM
# @Author  : w8ay
# @File    : wappalyzer.py

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase
from W13SCAN.lib.wappanalyzer import fingter


class W13SCAN(PluginBase):
    name = '基础信息收集'
    desc = ''''''
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

        ret = fingter(resp_str, self.response.build_headers())
        for k, v in ret.items():
            v = str(v)
        if ret:
            out.success(url, self.name, **ret)
