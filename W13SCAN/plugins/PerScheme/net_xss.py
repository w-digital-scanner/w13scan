#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/7 4:15 PM
# @Author  : w8ay
# @File    : net_xss.py
from urllib.parse import urlparse

import requests

from lib.core.common import random_str, generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '.net 通杀xss'

    def audit(self):
        p = urlparse(self.requests.url)
        domain = "{}://{}/".format(p.scheme, p.netloc)

        payload = "(A({}))/".format(random_str(6))
        url = domain + payload

        req = requests.get(url, headers=self.requests.headers)
        if payload in req.text:
            new_payload = "(A(\"onerror='{}'{}))/".format(random_str(6), random_str(6))
            url2 = domain + new_payload
            req2 = requests.get(url2, headers=self.requests.headers)
            if new_payload in req2.text:
                result = self.new_result()
                result.init_info(self.requests.url, ".net 通杀xss", VulType.XSS)
                result.add_detail("payload回显", req.reqinfo, generateResponse(req),
                                  "payload:{}回显在页面".format(payload), "", "", PLACE.GET)
                result.add_detail("payload回显", req2.reqinfo, generateResponse(req2),
                                  "payload:{}回显在页面".format(payload), "", "", PLACE.GET)
                self.success(result)
