#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/4 10:48 AM
# @Author  : w8ay
# @File    : command_system.py
import copy
import os
import random
import re

import requests

from W13SCAN.lib.const import acceptedExt, ignoreParams, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '系统命令注入'
    desc = '''测试系统命令注入，支持Windows/Linux,暂只支持Get请求方式和回显型的命令注入'''
    level = Level.HIGHT

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
            if self.response.system and self.response.system == "WINDOWS":
                del url_flag["echo `echo 6162983|base64`6162983".format(randint)]

            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                data = copy.deepcopy(params)
                for spli in ['', ';']:
                    for flag, re_list in url_flag.items():
                        if spli == "":
                            data[k] = flag
                        else:
                            data[k] = v + spli + flag
                        r = requests.get(netloc, params=data, headers=headers)
                        html1 = r.text
                        for rule in re_list:
                            if re.search(rule, html1, re.I | re.S | re.M):
                                out.success(url, self.name, payload="{}:{}".format(k, data[k]), raw=r.raw)
                                break
