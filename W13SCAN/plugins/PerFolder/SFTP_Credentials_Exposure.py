#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 3:07 PM
# @Author  : w8ay
# @File    : SFTP_Credentials_Exposure.py
import re

import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = ''''''
    name = 'SFTP_Credentials_Exposure'
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

        variants = [
            "/sftp-config.json",
            "/recentservers.xml"
        ]
        for f in variants:
            _ = url.rstrip('/') + f
            try:
                r = requests.get(_, headers=headers)
                if re.search(r'("type":[\s\S]*?"host":[\s\S]*?"user":[\s\S]*?"password":[\s\S]*")', r.text,
                             re.I | re.S | re.M):
                    out.success(_, self.name)
                elif re.search(r'(<Pass>[\s\S]*?<\/Pass>)', r.text, re.I):
                    out.success(_, self.name)
            except Exception as e:
                pass
