#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 8:22 PM
# @Author  : w8ay
# @File    : analyze_parameter.py
from W13SCAN.lib.common import isJavaObjectDeserialization, isPythonObjectDeserialization, \
    isPHPObjectDeserialization, paramToDict
from W13SCAN.lib.const import PLACE, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'base64,反序列化参数分析'
    desc = '''从参数，post包，cookie中寻找并解密base64和反序列化的参数'''
    level = Level.MIDDLE

    def _check(self, k, v, method, url, data):

        # ret = is_base64(v)

        # if ret and len(ret) >= 6:
        #     if method == "GET":
        #         out.success(url, self.name, method=method, parameter=k + ":" + v, base64decode=ret)
        #     elif method == "POST":
        #         out.success(url, self.name, method=method, parameter=k + ":" + v, base64decode=ret, data=str(data))

        whats = None
        if isJavaObjectDeserialization(v):
            whats = "JavaObjectDeserialization"
        elif isPHPObjectDeserialization(v):
            whats = "PHPObjectDeserialization"
        elif isPythonObjectDeserialization(v):
            whats = "PythonObjectDeserialization"
        if whats:
            if method == "GET":
                out.success(url, self.name, method=method, parameter=k + ":" + v, what=whats)
            elif method == "POST":
                out.success(url, self.name, method=method, parameter=k + ":" + v, what=whats, data=str(data))

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL
        data = self.requests.get_body_data().decode(self.response.decoding or 'utf-8')

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        if params:
            for k, v in params.items():
                if len(v) > 1024:
                    continue
                self._check(k, v, method, url, data)

        if method == "POST":
            if self.requests.post_data:
                for k, v in self.requests.post_data:
                    if len(v) > 1024:
                        continue
                    self._check(k, v, method, url, data)

        if headers and "cookie" in headers:
            cookie = paramToDict(headers["cookie"], place=PLACE.COOKIE)
            if cookie:
                for k, v in cookie.items():
                    if len(v) > 1024:
                        continue
                    self._check(k, v, method, url, data)
