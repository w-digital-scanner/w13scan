#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 9:09 PM
# @Author  : w8ay
# @File    : errinfo.py
import copy
import os

import requests

from lib.core.common import get_middle_text, generateResponse
from lib.core.data import conf
from lib.core.enums import WEB_PLATFORM, HTTPMETHOD, PLACE, VulType
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''对于一些php网站，将正常参数替换为[]可能造成真实信息泄漏'''
    name = 'php 真实路径泄漏'

    def audit(self):
        headers = self.requests.headers

        if WEB_PLATFORM.PHP not in self.response.programing and conf.level < 2:
            return

        iterdatas = self.generateItemdatas()

        for item in iterdatas:
            iterdata, positon = item
            for k, v in iterdata.items():
                data = copy.deepcopy(iterdata)
                del data[k]
                key = k + "[]"
                data[key] = v

                if positon == PLACE.GET:
                    r = requests.get(self.requests.netloc, params=data, headers=headers)
                elif positon == PLACE.POST:
                    r = requests.post(self.requests.url, data=data, headers=headers)
                elif positon == PLACE.COOKIE:
                    if self.requests.method == HTTPMETHOD.GET:
                        r = requests.get(self.requests.url, headers=headers, cookies=data)
                    elif self.requests.method == HTTPMETHOD.POST:
                        r = requests.post(self.requests.url, data=self.requests.post_data, headers=headers,
                                          cookies=data)
                if "Warning" in r.text and "array given in " in r.text:
                    path = get_middle_text(r.text, 'array given in ', ' on line')
                    result = self.new_result()
                    result.init_info(self.requests.url, self.desc, VulType.SENSITIVE)
                    result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                      "将参数{k}={v}替换为{k}[]={v},path路径泄漏:{p}".format(k=k, v=v, p=path), key, v, positon)
                    self.success(result)
