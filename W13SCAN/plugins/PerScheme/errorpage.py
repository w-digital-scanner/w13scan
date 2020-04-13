#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 3:55 PM
# @Author  : w8ay
# @File    : errorpage.py

import re
from urllib.parse import urlparse

import requests

from lib.core.common import random_str, generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '错误暴露信息'
    desc = '''访问一个不存在的错误页面，可以从这个页面中获取一些信息'''

    def audit(self):
        headers = self.requests.headers
        p = urlparse(self.requests.url)

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
                result = self.new_result()
                result.init_info(self.requests.url, "错误的配置信息", VulType.SENSITIVE)
                result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                  "匹配组件:{} 匹配正则:{}".format(k, v), "", "", PLACE.GET)
                self.success(result)
                break
