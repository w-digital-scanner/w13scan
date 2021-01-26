#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/15 3:52 PM
# @Author  : w8ay
# @File    : xss.py
import copy
import html
import random
import re
import string
from urllib.parse import unquote

import requests

from lib.core.common import random_str, generateResponse, url_dict2str
from lib.core.data import conf
from lib.core.enums import HTTPMETHOD, PLACE, VulType
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase
from lib.core.settings import XSS_EVAL_ATTITUDES, TOP_RISK_GET_PARAMS
from lib.helper.htmlparser import SearchInputInResponse, random_upper, getParamsFromHtml
from lib.helper.jscontext import SearchInputInScript


class W13SCAN(PluginBase):
    name = 'SSTI模板注入探测插件'

    def init(self):
        self.result = ResultObject(self)
        self.result.init_info(self.requests.url, "模板注入", VulType.SSTI)

    def getSSTIPayload(self, randint1=444, randint2=666) -> list:
        '''
        顺便检测下模板注入～
        return ['{123*1111}', '<%=123*1111%>', '#{123*1111}', '${{123*1111}}', '{{123*1111}}', '{{= 123*1111}}', '<# 123*1111>', '{@123*1111}', '[[123*1111]]', '${{"{{"}}123*1111{{"}}"}}']

        :return: list
        '''
        r = []
        payloads = [
            "{%d*%d}",
            "<%%=%d*%d%%>",
            "#{%d*%d}",
            "${{%d*%d}}",
            "{{%d*%d}}",
            "{{= %d*%d}}",
            "<# %d*%d>",
            "{@%d*%d}",
            "[[%d*%d]]",
            "${{\"{{\"}}%d*%d{{\"}}\"}}",
        ]
        for item in payloads:
            r.append(
                item % (randint1, randint2)
            )
        return r

    def audit(self):

        parse_params = set(getParamsFromHtml(self.response.text))
        resp = self.response.text
        params_data = {}
        self.init()
        iterdatas = []
        if self.requests.method == HTTPMETHOD.GET:
            parse_params = (parse_params | TOP_RISK_GET_PARAMS) - set(self.requests.params.keys())
            for key in parse_params:
                params_data[key] = random_str(6)
            params_data.update(self.requests.params)
            resp = requests.get(self.requests.netloc, params=params_data, headers=self.requests.headers).text
            iterdatas = self.generateItemdatas(params_data)
        elif self.requests.method == HTTPMETHOD.POST:
            parse_params = (parse_params) - set(self.requests.post_data.keys())
            for key in parse_params:
                params_data[key] = random_str(6)
            params_data.update(self.requests.post_data)
            resp = requests.post(self.requests.url, data=params_data, headers=self.requests.headers).text
            iterdatas = self.generateItemdatas(params_data)

        for origin_dict, position in iterdatas:
            if position == PLACE.URI:
                continue
            for k, v in origin_dict.items():
                v = unquote(v)
                if v not in resp:
                    continue
                data = copy.deepcopy(origin_dict)
                # ssti检测
                r1 = self.test_ssti(data, k, position)
                if r1:
                    r2 = self.test_ssti(data, k, position)
                    if r2:
                        result = self.new_result()
                        result.init_info(self.requests.url, "SSTI模板注入", VulType.XSS)
                        result.add_detail("第一次payload请求", r1["request"], r1["response"],
                                          r1["desc"], k, r1["payload"], positon)
                        result.add_detail("第二次payload请求", r2["request"], r2["response"],
                                          r2["desc"], k, r2["payload"], positon)
                        self.success(result)
                        break

        if len(self.result.detail) > 0:
            self.success(self.result)

    def test_ssti(self, data, k, positon):
        randnum1 = random.randint(1000, 10000)
        randnum2 = random.randint(8888, 20000)
        checksum = str(randnum1 * randnum2)
        ssti_payloads = self.getSSTIPayload(randnum1, randnum2)
        for payload in ssti_payloads:
            data[k] = payload
            # 不编码请求
            r1 = self.req(positon, url_dict2str(data, positon))
            if checksum in r1.text:
                return {
                    "request": r1.reqinfo,
                    "response": generateResponse(r1),
                    "desc": "payload:{} 会回显{} 不编码payload".format(payload, checksum),
                    "payload": payload
                }
            # url编码请求
            r1 = self.req(positon, data)
            if checksum in r1.text:
                return {
                    "request": r1.reqinfo,
                    "response": generateResponse(r1),
                    "desc": "payload:{} 会回显{} url编码payload".format(payload, checksum),
                    "payload": payload
                }
            # html编码请求
            data[k] = html.escape(data[k])
            r1 = self.req(positon, data)
            if checksum in r1.text:
                return {
                    "request": r1.reqinfo,
                    "response": generateResponse(r1),
                    "desc": "payload:{} 会回显{} html编码payload".format(payload, checksum),
                    "payload": payload
                }

