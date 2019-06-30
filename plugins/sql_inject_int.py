#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 10:56 AM
# @Author  : w8ay
# @File    : sql_inject_int.py
import copy
import os
import random
import re
from urllib.parse import urlparse

import requests

from lib.common import get_links, prepare_url
from lib.const import acceptedExt
from lib.data import Share
from lib.helper.diifpage import fuzzy_equal
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '数字型SQL注入'
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
            links = [url]
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

                for k, v in params.items():
                    if not re.search('^-?\d+(\.\d+)?$', v):
                        continue
                    data = copy.deepcopy(params)
                    # 判断条件:
                    # 1. -randint !== origin
                    # 2. +randint-randint == origin
                    payload1 = "{0}+{1}".format(v, random.randint(10, 100))
                    data[k] = payload1
                    url1 = prepare_url(netloc, params=data)
                    if Share.in_url(url1):
                        continue
                    Share.add_url(url1)
                    r = requests.get(url1, headers=headers)
                    html1 = r.text
                    if fuzzy_equal(resp_str, html1, 0.8):
                        continue
                    payload2 = "{0}+{1}-{1}".format(v, random.randint(10, 100))
                    data[k] = payload2
                    r2 = requests.get(netloc, params=data, headers=headers)
                    html2 = r2.text
                    if fuzzy_equal(resp_str, html2, 0.8):
                        msg = " {k}:{v} !== {k}:{v1} and {k}:{v} === {k}:{v2}".format(k=k, v=v, v1=payload1,
                                                                                      v2=payload2)
                        # out.log(msg)
                        out.success(link, self.name, payload=k, condition=msg)
                        break
