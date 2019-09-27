#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/9/26 10:29 PM
# @Author  : w8ay
# @File    : webpack.py
import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'webpack 前端泄露'
    desc = '''攻击者可通过该文件重建出系统目录结构，打开按F12可看到webpack://目录，在里面可以找到相关的内部目录结果及接口信息，建议修改webpack配置为build模式并且按需加载。'''
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

        if url.lower().endswith(".js"):
            test_url = url + ".map"
            r = requests.get(test_url, headers=headers)
            if r.status_code == 200 and "webpack:/" in r.text:
                out.success(test_url, self.name, desc=self.desc)
