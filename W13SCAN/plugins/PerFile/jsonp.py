#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 4:45 PM
# @Author  : w8ay
# @File    : jsonp.py

import string

import requests
import json
import re
from W13SCAN.lib.common import random_str
from W13SCAN.lib.const import JSON_RECOGNITION_REGEX, Level
from W13SCAN.lib.helper.diifpage import GetRatio
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'JSONP寻找插件'
    desc = '''自动寻找JSONP请求并自动去除referer查看能否利用'''
    level = Level.LOW

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

        combine = '^\S+\(\{.*?\}\)'
        domain = "{}://{}".format(p.scheme, p.netloc) + random_str(4,
                                                                   string.ascii_lowercase + string.digits) + ".com/"

        sensitive_params = ['mail', 'user', 'name', 'ip', 'pass', 'add', 'phone']
        if re.match(combine, resp_str, re.I | re.S):
            # 判断是否为jsonp
            headers["Referer"] = domain
            if method == 'GET':
                r = requests.get(url, headers=headers)
                if GetRatio(resp_str, r.text) >= 0.8:
                    for i in sensitive_params:
                        if i in r.text.lower():
                            res = {
                                "Referer": domain,
                                "keyword": i,
                                "Content-Type": r.headers.get("Content-Type", "")
                            }
                            response = self.jsonp_load(r.text)
                            if response:
                                res["response"] = response
                                if len(response) > 500:
                                    res["response"] = "数据太多，自行访问"
                            out.success(url, self.name, **res)
        elif re.match(JSON_RECOGNITION_REGEX, resp_str, re.I | re.S) and 'callback' not in url:
            # 不是jsonp,是json
            headers["Referer"] = domain
            params["callback"] = random_str(2)
            if method == 'GET':
                r = requests.get(netloc, params=params, headers=headers)
                if r.text.startswith(params["callback"] + "({"):
                    res = {
                        "Referer": domain,
                        "Content-Type": r.headers.get("Content-Type", ""),
                        "callback": params["callback"],
                    }
                    response = self.jsonp_load(r.text)
                    if response:
                        res["response"] = response
                        if len(response) > 500:
                            res["response"] = "数据太多，自行访问"
                    out.success(r.url, self.name, **res)
