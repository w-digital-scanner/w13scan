#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 3:18 PM
# @Author  : w8ay
# @File    : sourceleak.py
import re

import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''基于流量动态查找目录下仓库源码泄漏'''
    name = '.git .svn .bzr .hg泄漏插件'
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

        flag = {
            "/.svn/all-wcprops": "svn:wc:ra_dav:version-url",
            "/.git/config": 'repositoryformatversion[\s\S]*',
            "/.bzr/README": 'This\sis\sa\sBazaar[\s\S]',
            '/CVS/Root': ':pserver:[\s\S]*?:[\s\S]*',
            '/.hg/requires': '^revlogv1.*'
        }
        for f in flag.keys():
            _ = url.rstrip('/') + f
            try:
                r = requests.get(_, headers=headers)
                if re.search(flag[f], r.text, re.I | re.S | re.M):
                    out.success(_, self.name)
            except Exception as e:
                pass
