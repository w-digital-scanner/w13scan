#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 3:18 PM
# @Author  : w8ay
# @File    : sourceleak.py
import re

import requests

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''基于流量动态查找目录下仓库源码泄漏'''
    name = '.git .svn .bzr .hg泄漏插件'

    def audit(self):

        flag = {
            "/.svn/all-wcprops": "svn:wc:ra_dav:version-url",
            "/.git/config": 'repositoryformatversion[\s\S]*',
            "/.bzr/README": 'This\sis\sa\sBazaar[\s\S]',
            '/CVS/Root': ':pserver:[\s\S]*?:[\s\S]*',
            '/.hg/requires': '^revlogv1.*'
        }
        headers = self.requests.headers
        for f in flag.keys():
            _ = self.requests.url.rstrip('/') + f
            r = requests.get(_, headers=headers)
            if re.search(flag[f], r.text, re.I | re.S | re.M):
                result = self.new_result()
                result.init_info(self.requests.url, "仓库泄漏", VulType.SENSITIVE)
                result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                  "匹配到正则:{}".format(flag[f]), "", "", PLACE.GET)
                self.success(result)
