#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 3:55 PM
# @Author  : w8ay
# @File    : errorpage.py

import re

import requests

from W13SCAN.lib.common import random_str
from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '错误暴露信息'
    desc = '''访问一个不存在的错误页面，可以从这个页面中获取一些信息'''
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

        domain = "{}://{}/".format(p.scheme, p.netloc) + random_str(6) + ".jsp"

        re_list = {
            "ASPNETPathDisclosure": "<title>Invalid\sfile\sname\sfor\smonitoring:\s'([^']*)'\.\sFile\snames\sfor\smonitoring\smust\shave\sabsolute\spaths\,\sand\sno\swildcards\.<\/title>",
            "Struts2DevMod": "You are seeing this page because development mode is enabled.  Development mode, or devMode, enables extra",
            "Django DEBUG MODEL": "You're seeing this error because you have <code>DEBUG = True<\/code> in",
            "RailsDevMode": "<title>Action Controller: Exception caught<\/title>",
            "RequiredParameter": "Required\s\w+\sparameter\s'([^']+?)'\sis\snot\spresent",
            "Thinkphp3 Debug": '<p class="face">:\(</p>'
        }
        r = requests.get(domain, headers=headers)
        for k, v in re_list.items():
            if re.search(v, r.text, re.S | re.I):
                out.success(domain, self.name, name=k)
                break
