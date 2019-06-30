#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 9:09 PM
# @Author  : w8ay
# @File    : errinfo.py
import copy
import os
from urllib.parse import urlparse

import requests

from lib.common import prepare_url
from lib.data import Share
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''对于一些php网站，将正常参数替换为[]可能造成真实信息泄漏'''
    name = 'php 真实路径泄漏'

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL
        data = self.requests.get_body_data().decode()  # POST 数据

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = urlparse(url)
        # 判断带有php或无后缀的
        basepath = os.path.basename(p.path)
        if "." in basepath and ".php" not in basepath:
            return

        if "Warning" in resp_str and "array given" in resp_str:
            out.success(url, self.name)

        params = dict()
        for i in p.query.split("&"):
            try:
                key, value = i.split("=")
                params[key] = value
            except ValueError:
                pass
        netloc = "{}://{}{}".format(p.scheme, p.netloc, p.path)
        for k, v in params.items():
            data = copy.deepcopy(params)
            del data[k]
            data[k + "[]"] = v
            try:
                _ = prepare_url(netloc, params=data)
                if Share.in_url(_):
                    continue
                Share.add_url(_)
                r = requests.get(_, headers=headers)
                if "Warning" in r.text and "array given" in r.text:
                    out.success(_, self.name)
            except:
                pass
