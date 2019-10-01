#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/9/27 5:23 PM
# @Author  : w8ay
# @File    : http_smuggling.py
import requests
from requests import Request, Session
from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'http smuggling 走私攻击'
    desc = '''由于前后端处理http协议时的差异，造成走私攻击，或由此获取敏感信息，本插件只有检测功能'''
    level = Level.MIDDLE

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

        cycle = 5
        timeout = 30

        if self.response.status != 200:
            return
        # request_smuggling_cl_te
        for i in range(cycle):
            payload_headers = {
                "Content-Length": "6",
                "Transfer-Encoding": "chunked"
            }
            data = b'0\r\n\r\nS'.decode()
            temp_header = headers.copy()
            for k, v in payload_headers.items():
                if k.lower() in temp_header:
                    temp_header[k.lower()] = v
                else:
                    temp_header[k] = v
            try:
                r = requests.post(url, headers=temp_header, data=data, timeout=30)
            except:
                continue
            if r.status_code == 403 and resp_str != r.text:
                r2 = requests.get(url, headers=headers)
                if r2 == 200:
                    out.success(url, self.name, method='POST', **payload_headers, type="CL.TE型",
                                data='0\\r\\n\\r\\nS', )
                    return
        # request_smuggling_te_cl
        for i in range(cycle + 1):
            payload_headers = {
                "Content-Length": "3",
                "Transfer-Encoding": "chunked"
            }
            data = b'1\r\nD\r\n0\r\n\r\n'.decode()
            req = Request('POST', url, data=data, headers=headers)
            prepped = req.prepare()
            for k, v in payload_headers.items():
                if k.lower() in prepped.headers:
                    del prepped.headers[k.lower()]
                prepped.headers[k] = v
            s = Session()
            try:
                r = s.send(prepped)
            except:
                continue
            if r.status_code == 403 and resp_str != r.text:
                r2 = requests.get(url, headers=headers)
                if r2.status_code == 200:
                    out.success(url, self.name, method='POST', **payload_headers, type="TE.CL型",
                                data='1\\r\\nD\\r\\n0\\r\\n\\r\\nS')
                    return
