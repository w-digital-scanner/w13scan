#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/7 2:40 PM
# @Author  : w8ay
# @File    : post_sql_inject_error.py

import copy

import requests

from W13SCAN.lib.const import ignoreParams, POST_HINT, Level
from W13SCAN.lib.helper.helper_sqli import Get_sql_errors
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'POST插件 基于报错SQL注入'
    desc = '''目前支持POST方式的请求'''
    level = Level.HIGHT

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL

        post_hint = self.requests.post_hint
        post_data = self.requests.post_data

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        if method == 'POST':
            if post_hint == POST_HINT.NORMAL:
                sql_flag = '鎈\'"\('
                for k, v in post_data.items():
                    if k.lower() in ignoreParams:
                        continue
                    data = copy.deepcopy(post_data)
                    data[k] = v + sql_flag
                    r = requests.post(url, headers=headers, data=data)
                    html = r.text
                    for sql_regex, dbms_type in Get_sql_errors():
                        match = sql_regex.search(html)

                        if match:
                            out.success(url, self.name, payload="{}={}".format(k, data[k]), data=str(data),
                                        dbms=str(dbms_type), raw=r.raw)
                            break
