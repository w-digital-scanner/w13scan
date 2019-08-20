#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 9:09 PM
# @Author  : w8ay
# @File    : errinfo.py
import copy
import os

import requests

from W13SCAN.lib.common import prepare_url, get_middle_text
from W13SCAN.lib.const import ignoreParams, acceptedExt, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''对于一些php网站，将正常参数替换为[]可能造成真实信息泄漏'''
    name = 'php 真实路径泄漏'
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

        if p.query == '':
            return
        exi = os.path.splitext(p.path)[1]
        if exi not in acceptedExt:
            return
        if self.response.language and self.response.language != "PHP":
            return

        if "Warning" in resp_str and "array given" in resp_str:
            out.success(url, self.name)

        for k, v in params.items():
            if k.lower() in ignoreParams:
                continue
            data = copy.deepcopy(params)
            del data[k]
            data[k + "[]"] = v
            try:
                _ = prepare_url(netloc, params=data)
                r = requests.get(_, headers=headers)
                if "Warning" in r.text and "array given" in r.text:
                    path = get_middle_text(r.text, 'array given in ', ' on line')
                    out.success(_, self.name, path=path, raw=r.raw)
            except:
                pass
