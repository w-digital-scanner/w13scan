#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/21 5:02 PM
# @Author  : w8ay
# @File    : sensitive_folders.py.py


import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.controller import task_push
from W13SCAN.lib.data import KB
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase
from W13SCAN.plugins.loader import FakeReq, FakeResp


class W13SCAN(PluginBase):
    name = '敏感目录扫描'
    desc = ''''''
    level = Level.LOW

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

        domain = "{}://{}/".format(p.scheme, p.netloc)

        folders = ['/admin', '/bak', '/backup', '/conf', '/config', '/db', '/debug', '/data', '/database', '/deploy',
                   '/WEB-INF',
                   '/install', '/manage', '/manager', '/monitor', '/tmp', '/temp', '/test']

        for folder in folders:
            test_url = domain.rstrip('/') + folder
            r = requests.get(test_url, headers=headers, allow_redirects=False)
            if r.status_code in (301, 302):
                location = headers.get('Location', '')
                if test_url + '/' == location:
                    out.success(test_url, self.name)

                    if not KB["spiderset"].add('GET' + test_url, 'get_link_directory'):
                        continue
                    try:
                        req = FakeReq(test_url, headers)
                        resp = FakeResp(r)
                    except:
                        continue
                    if KB["spiderset"].add('GET' + resp._url, 'PerFolder'):
                        task_push('PerFolder', req, resp)
