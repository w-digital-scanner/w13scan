#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 3:21 PM
# @Author  : w8ay
# @File    : sql_inject_error.py
import copy
import os
from urllib.parse import urlparse

import requests

from lib.common import get_links, prepare_url
from lib.const import acceptedExt, ignoreParams
from lib.data import Share
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
        data = self.requests.get_body_data().decode()  # POST 数据

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        if method == 'GET':
            # 从源码中获取更多链接
            links = get_links(resp_str, url, True)
            links.append(url)
            for link in set(links):
                # 只接收指定类型的SQL注入
                p = urlparse(link)
                if p.query == '':
                    continue
                exi = os.path.splitext(p.path)[1]
                if exi not in acceptedExt:
                    continue
                params = dict()
                for i in p.query.split("&"):
                    try:
                        key, value = i.split("=")
                        params[key] = value
                    except ValueError:
                        pass
                netloc = "{}://{}{}".format(p.scheme, p.netloc, p.path)

                sql_flag = '鎈\'"\('
                for k, v in params.items():
                    if k.lower() in ignoreParams:
                        continue
                    data = copy.deepcopy(params)
                    data[k] = v + sql_flag
                    url1 = prepare_url(netloc, params=data)
                    if Share.in_url(url1):
                        continue
                    Share.add_url(url1)
                    r = requests.get(url1, headers=headers)
                    html = r.text
                    for sql_regex, dbms_type in Get_sql_errors():
                        match = sql_regex.search(html)
                        if match:
                            print(sql_regex.pattern, dbms_type)
                            out.success(link, self.name, payload="{}={}".format(k, data[k]))
                            break
