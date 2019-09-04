#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 3:21 PM
# @Author  : w8ay
# @File    : sql_inject_error.py
import copy
import os
from urllib.parse import urlencode

import requests

from W13SCAN.lib.common import prepare_url, paramToDict
from W13SCAN.lib.const import acceptedExt, ignoreParams, PLACE, Level
from W13SCAN.lib.helper.helper_sqli import Get_sql_errors
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '基于报错SQL注入'
    desc = '''支持GET、COOKIE、HEADER头注入'''
    level = Level.HIGHT

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

        success = False
        origin_len = len(resp_str)
        sql_flag = '鎈\'"\('
        if headers and "cookie" in headers:
            cookies = paramToDict(headers["cookie"], place=PLACE.COOKIE)
            tmp_headers = copy.deepcopy(headers)
            del tmp_headers["cookie"]
            if cookies:
                for k, v in cookies.items():
                    cookie = copy.deepcopy(cookies)
                    cookie[k] = v + sql_flag
                    r = requests.get(url, headers=tmp_headers, cookies=urlencode(cookie))
                    if origin_len == len(r.text):
                        continue
                    for sql_regex, dbms_type in Get_sql_errors():
                        match = sql_regex.search(r.text)
                        if match:
                            out.success(url, self.name, payload="cookie: {}={}".format(k, cookie[k]),
                                        dbms_type=dbms_type,
                                        errinfo=match.group(),
                                        raw=r.raw)
                            success = True
                            break
        if success:
            return
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
                        out.success(url, self.name, payload="{}={}".format(k, data[k]), dbms_type=dbms_type, raw=r.raw,
                                    errinfo=match.group())
                        success = True
                        break
            if success:
                return
            # test header
            if headers:
                sql_flag = '\'"\('
                new_headers = {"user-agent": headers.get("User-Agent", "") + sql_flag,
                               # "referer": headers.get("referer", url) + sql_flag,
                               "x-forwarded-for": headers.get("x-forwarded-for", "127.0.0.1") + sql_flag,
                               "via": headers.get("via", "") + sql_flag
                               }
                headers.update(new_headers)
                r = requests.get(url, headers=headers)
                html = r.text
                if origin_len == len(html):
                    return
                for sql_regex, dbms_type in Get_sql_errors():
                    match = sql_regex.search(html)
                    if match:
                        out.success(url, self.name, type="header inject", dbms_type=dbms_type, raw=r.raw,
                                    errinfo=match.group())
                        success = True
                        break
