#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/9/27 5:23 PM
# @Author  : w8ay
# @File    : http_smuggling.py
import requests
from requests import Request, Session

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'http smuggling 走私攻击'
    desc = '''由于前后端处理http协议时的差异，造成走私攻击，或由此获取敏感信息，本插件只有检测功能'''

    def audit(self):
        url = self.requests.url
        headers = self.requests.headers
        cycle = 5

        if self.response.status_code != 200:
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
            if r.status_code == 403 and self.response.text != r.text:
                r2 = requests.get(url, headers=headers)
                if r2 == 200:
                    result = self.new_result()
                    result.init_info(self.requests.url, "http smuggling 走私攻击", VulType.SMUGGLING)
                    result.add_detail("发送畸形包", r.reqinfo, generateResponse(r),
                                      "request_smuggling CL.TE型", "", "", PLACE.POST)
                    result.add_detail("访问正常网页", r2.reqinfo, generateResponse(r2), "", "", "", PLACE.GET)
                    self.success(result)
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
            if r.status_code == 403 and self.response.text != r.text:
                r2 = requests.get(url, headers=headers)
                if r2.status_code == 200:
                    result = self.new_result()
                    result.init_info(self.requests.url, "http smuggling 走私攻击", VulType.SMUGGLING)
                    result.add_detail("发送畸形包", r.reqinfo, generateResponse(r),
                                      "request_smuggling TE.CL型", "", "", PLACE.POST)
                    result.add_detail("访问正常网页", r2.reqinfo, generateResponse(r2), "", "", "", PLACE.GET)
                    self.success(result)
                    return
