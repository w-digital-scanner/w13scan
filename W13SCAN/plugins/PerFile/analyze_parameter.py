#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 8:22 PM
# @Author  : w8ay
# @File    : analyze_parameter.py
from api import PluginBase, ResultObject, VulType
from api import isJavaObjectDeserialization, isPHPObjectDeserialization, isPythonObjectDeserialization


class W13SCAN(PluginBase):
    name = '反序列化参数分析插件'

    def _check(self, k, v):
        whats = None
        if isJavaObjectDeserialization(v):
            whats = "JavaObjectDeserialization"
        elif isPHPObjectDeserialization(v):
            whats = "PHPObjectDeserialization"
        elif isPythonObjectDeserialization(v):
            whats = "PythonObjectDeserialization"
        if whats:
            result = ResultObject(self)
            text_result = "发现{}反序列化参数".format(whats)
            result.init_info(self.requests.url, text_result, VulType.BASELINE)
            result.add_detail("原始请求", self.requests.raw, self.response.raw, "参数{}发现为{}的反序列化结果".format(k, whats), k,
                              v, self.requests.method)
            self.success(result)

    def audit(self):
        params = self.requests.params
        data = self.requests.post_data
        cookies = self.requests.cookies

        if params:
            for k, v in params.items():
                if len(v) > 1024:
                    continue
                self._check(k, v)

        if data:
            for k, v in data.items():
                if len(v) > 1024:
                    continue
                self._check(k, v)

        if cookies:
            for k, v in cookies.items():
                if len(v) > 1024:
                    continue
                self._check(k, v)
