#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 4:46 PM
# @Author  : w8ay
# @File    : directory_browse.py
from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '目录遍历插件'
    desc = '''遍历每个目录，查看是否可以直接访问'''
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

        flag_list = [
            "directory listing for",
            "<title>directory",
            "<head><title>index of",
            '<table summary="directory listing"',
            'last modified</a>',

        ]
        for i in flag_list:
            if i in resp_str.lower():
                out.success(url, self.name)
                break
