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
from lib.helper.helper_sensitive import sensitive_page_error_message_check


class W13SCAN(PluginBase):
    name = '错误暴露信息'
    desc = '''访问一个不存在的错误页面，可以从这个页面中获取一些信息'''

    def audit(self):
        headers = self.requests.headers
        p = urlparse(self.requests.url)

        domain = "{}://{}/".format(p.scheme, p.netloc) + random_str(6) + ".jsp"
        r = requests.get(domain, headers=headers)
        messages = sensitive_page_error_message_check(r.text)
        if messages:
            result = self.new_result()
            result.init_info(self.requests.url, "敏感的报错信息", VulType.SENSITIVE)
            for m in messages:
                text = m["text"]
                _type = m["type"]
                result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                  "匹配组件:{} 匹配正则:{}".format(_type, text), "", "", PLACE.GET)

            self.success(result)
