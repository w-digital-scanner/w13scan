#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/7 11:18 AM
# @Author  : w8ay
# @File    : redirect.py
import copy
import os
import re

import requests

from lib.common import prepare_url, is_base64
from lib.const import ignoreParams, acceptedExt
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''任意网址重定向'''
    name = '支持检查 html meta 跳转、30x 跳转、JavaScript跳转等等'

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

        if p.query == '':
            return
        exi = os.path.splitext(p.path)[1]
        if exi not in acceptedExt:
            return

        if method == "GET":
            for k, v in list(params.items()):
                if not re.match('^http.+', v, re.I):
                    ret = is_base64(v)
                    if not (ret and re.match('^http.+', ret, re.I)):
                        continue
                data = copy.deepcopy(params)
                payload = "https://www.baidu.com/?q={}".format(url)
                data[k] = payload
                r = requests.get(netloc, params=data, headers=headers, allow_redirects=False)
                if r.status_code in [301.302]:
                    out.success(url, self.name, payload="{}:{}".format(k, payload), type="header头跳转")
                if r.status_code == 200:
                    if re.search('<meta http-equiv=["\']Refresh["\'] content=["\']\d+;url=.*?["\']>', r.text,
                                 re.I | re.S):
                        out.success(url, self.name, payload="{}:{}".format(k, payload), type="html meta跳转")
                    if re.search('window\.location\.(href|replace)', r.text, re.I | re.S):
                        out.success(url, self.name, payload="{}:{}".format(k, payload), type="javascript window跳转")
