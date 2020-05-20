#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 4:45 PM
# @Author  : w8ay
# @File    : jsonp.py

import string
from urllib.parse import urlparse

import pyjsparser
import requests
import json
import re

from pyjsparser import parse

from lib.core.common import random_str
from lib.core.enums import VulType, PLACE
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase
from lib.helper.helper_sensitive import sensitive_bankcard, sensitive_idcard, sensitive_phone, sensitive_email
from lib.helper.jscontext import analyse_Literal


class W13SCAN(PluginBase):
    name = 'JSONP寻找插件'
    desc = '''自动寻找JSONP请求并自动去除referer查看能否利用'''

    def jsonp_load(self, jsonp):
        match = re.search('^[^(]*?\((.*)\)[^)]*$', jsonp)
        if match is None:
            return None
        json_text = match.group(1)
        if not json_text:
            return None
        try:
            arr = json.loads(json_text)
        except:
            return None
        return str(arr)

    def info_search(self, text) -> dict:
        '''
        从一段文本中搜索敏感信息
        :param text:
        :return:
        '''
        sensitive_params = [sensitive_bankcard, sensitive_idcard, sensitive_phone, sensitive_email]
        sensitive_list = ['username', 'memberid', 'nickname', 'loginid', 'mobilephone', 'userid', 'passportid',
                          'profile', 'loginname', 'loginid',
                          'email', 'realname', 'birthday', 'sex', 'ip']

        for func in sensitive_params:
            ret = func(text)
            if ret:
                return ret
        for item in sensitive_list:
            if item.lower() == text.lower():
                return {"type": "keyword", "content": item}

    def check_sentive_content(self, resp: str) -> set:
        script = resp.strip()
        if not script:
            return set()
        if script[0] == "{":
            script = "d=" + script
        try:
            nodes = parse(script)["body"]
        except pyjsparser.pyjsparserdata.JsSyntaxError as e:
            return set()
        literals = analyse_Literal(nodes)
        result = set()
        for item in literals:
            v = self.info_search(item)
            if v:
                result.add(v["content"])
        return result

    def audit(self):

        callbaks = ["callback", "cb", "json"]
        params = self.requests.params
        isBreak = True
        for p in params.keys():
            if p.lower() in callbaks:
                isBreak = False
                break
        if isBreak:
            return
        result = self.check_sentive_content(self.response.text)
        if not result:
            return
        p = urlparse(self.requests.url)
        fake_domain = "{}://{}".format(p.scheme, p.netloc) + random_str(4,
                                                                        string.ascii_lowercase + string.digits) + ".com/"
        headers = self.requests.headers
        headers["Referer"] = fake_domain
        req = requests.get(self.requests.url, headers=headers)
        result2 = self.check_sentive_content(req.text)
        if not result2:
            return
        result = ResultObject(self)
        result.init_info(self.requests.url, "jsonp敏感信息", VulType.SENSITIVE)
        result.add_detail("payload探测", self.requests.raw, self.response.raw,
                          "发现敏感信息:{}".format(repr(result2)), "", "", PLACE.GET)
        self.success(result)
