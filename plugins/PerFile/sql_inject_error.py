#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 3:21 PM
# @Author  : w8ay
# @File    : sql_inject_error.py
import copy
import os
from urllib.parse import urlencode

import requests

from lib.common import prepare_url, paramToDict
from lib.const import acceptedExt, ignoreParams, PLACE
from lib.helper.helper_sqli import Get_sql_errors
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '基于报错SQL注入'
    desc = '''目前仅支持GET方式的请求'''

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

        # cookie
        exi = os.path.splitext(p.path)[1]
        if exi not in acceptedExt:
            return

        sql_flag = '鎈\'"\('
        if headers and "cookie" in headers:
            cookies = paramToDict(headers["cookie"], place=PLACE.COOKIE)
            del headers["cookie"]
            if cookies:
                for k, v in cookies.items():
                    cookie = copy.deepcopy(cookies)
                    cookie[k] = v + sql_flag
                    r = requests.get(url, headers, cookies=urlencode(cookie))
                    for sql_regex, dbms_type in Get_sql_errors():
                        match = sql_regex.search(r.text)
                        if match:
                            out.success(url, self.name, payload="cookie: {}={}".format(k, cookie[k]),
                                        dbms_type=dbms_type,
                                        raw=r.raw)
                            break
        if method == 'GET':
            if p.query == '':
                return
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return

            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                data = copy.deepcopy(params)
                data[k] = v + sql_flag
                url1 = prepare_url(netloc, params=data)
                r = requests.get(url1, headers=headers)
                html = r.text
                for sql_regex, dbms_type in Get_sql_errors():
                    match = sql_regex.search(html)
                    if match:
                        out.success(url, self.name, payload="{}={}".format(k, data[k]), dbms_type=dbms_type, raw=r.raw)
                        break
