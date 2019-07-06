#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 6:44 PM
# @Author  : w8ay
# @File    : cors.py


from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'CORS跨域资源共享'
    desc = '''寻找CORS能否利用'''

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL
        data = self.requests.get_body_data().decode(errors='ignore')

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        sensitive_params = ['mail', 'user', 'name', 'ip', 'pass', 'add', 'phone']
        if "access-control-allow-origin" in resp_headers and resp_headers["access-control-allow-origin"] == "*":
            if "access-control-allow-credentials" in resp_headers and resp_headers[
                "access-control-allow-credentials"].lower() == 'true':
                out.success(url, self.name, payload=str(data), method=method)
            else:
                for i in sensitive_params:
                    if i in resp_str:
                        out.success(url, self.name, sensitive=i, method=method, payload=str(data))
                        break
