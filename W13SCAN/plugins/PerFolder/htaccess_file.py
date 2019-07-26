#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 2:48 PM
# @Author  : w8ay
# @File    : htaccess_file.py

import requests
import re

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''.htaccess泄漏'''
    name = '.htaccess泄漏'
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

        testURL = url.strip('/') + "/.htaccess"
        r = requests.get(testURL, headers=headers)
        if re.search(
                '(RewriteEngine|RewriteCond|RewriteRule|AuthType|AuthName|AuthUserFile|ErrorDocument|deny from|AddType|AddHandler|IndexIgnore|ContentDigest|AddOutputFilterByType|php_flag|php_value)\s',
                r.text, re.I):
            out.success(testURL, self.name)
