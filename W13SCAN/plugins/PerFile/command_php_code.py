#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/4 11:49 AM
# @Author  : w8ay
# @File    : command_php_code.py
import copy
import random
import re

import requests

from api import VulType
from lib.core.common import md5, paramsCombination, generateResponse
from lib.core.data import conf
from lib.core.enums import WEB_PLATFORM, HTTPMETHOD, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'PHP代码注入'
    desc = '''PHP代码注入发现，可执行任意php代码'''

    def audit(self):
        headers = self.requests.headers

        if WEB_PLATFORM.PHP not in self.response.programing and conf.level < 2:
            return

        regx = 'Parse error: syntax error,.*?\sin\s'
        randint = random.randint(5120, 10240)
        verify_result = md5(str(randint).encode())
        payloads = [
            "print(md5({}));",
            ";print(md5({}));",
            "';print(md5({}));$a='",
            "\";print(md5({}));$a=\"",
            "${{@print(md5({}))}}",
            "${{@print(md5({}))}}\\",
            "'.print(md5({})).'"
        ]
        iterdatas = []
        if self.requests.method == HTTPMETHOD.GET:
            iterdatas.append((self.requests.params, PLACE.GET))
        elif self.requests.method == HTTPMETHOD.POST:
            iterdatas.append((self.requests.post_data, PLACE.POST))
        if conf.level >= 3:
            iterdatas.append((self.requests.cookies, PLACE.COOKIE))

        for item in iterdatas:
            iterdata, positon = item
            for k, v in iterdata.items():
                data = copy.deepcopy(iterdata)
                for payload in payloads:
                    if payload[0] == "p":
                        data[k] = payload.format(randint)
                    else:
                        data[k] = v + payload.format(randint)

                    params = paramsCombination(data, positon)
                    if positon == PLACE.GET:
                        r = requests.get(self.requests.netloc, params=params, headers=headers)
                    elif positon == PLACE.POST:
                        r = requests.post(self.requests.url, data=params, headers=headers)
                    elif positon == PLACE.COOKIE:
                        if self.requests.method == HTTPMETHOD.GET:
                            r = requests.get(self.requests.url, headers=headers, cookies=params)
                        elif self.requests.method == HTTPMETHOD.POST:
                            r = requests.post(self.requests.url, data=self.requests.post_data, headers=headers,
                                              cookies=params)
                    html1 = r.text

                    if verify_result in html1:
                        result = self.new_result()
                        result.init_info(self.requests.url, self.desc, VulType.CMD_INNJECTION)
                        result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                          "探测payload:{}并发现回显:{}".format(data[k], verify_result), k, data[k], positon)
                        self.success(result)
                        break
                    if re.search(regx, html1, re.I | re.S | re.M):
                        result = self.new_result()
                        result.init_info(self.requests.url, self.desc, VulType.CMD_INNJECTION)
                        result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                          "探测payload:{}并发现正则回显:{},可能是payload未闭合语句造成的错误".format(data[k], regx), k,
                                          data[k], positon)
                        self.success(result)
                        break
