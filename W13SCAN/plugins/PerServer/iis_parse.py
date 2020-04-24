#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/20 8:49 PM
# @Author  : w8ay
# @File    : iis_parse.py
from urllib.parse import urlparse

import requests

from lib.core.common import generateResponse
from lib.core.data import conf
from lib.core.enums import WEB_PLATFORM, VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'iis解析漏洞'

    def audit(self):
        if WEB_PLATFORM.PHP in self.response.programing or conf.level >= 2:
            headers = self.requests.headers
            p = urlparse(self.requests.url)
            domain = "{}://{}/".format(p.scheme, p.netloc)
            payload = domain + "robots.txt/.php"
            r = requests.get(payload, headers=headers, allow_redirects=False)
            ContentType = r.headers.get("Content-Type", '')
            if 'html' in ContentType and "allow" in r.text:
                result = self.new_result()
                result.init_info(self.requests.url, "代码解析漏洞", VulType.CODE_INJECTION)
                result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                  "Content-Type:{}".format(ContentType), "", "", PLACE.GET)
                self.success(result)
