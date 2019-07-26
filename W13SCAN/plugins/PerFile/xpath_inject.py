#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/16 4:52 PM
# @Author  : w8ay
# @File    : xpath_inject.py
import copy
import os
import re

import requests

from W13SCAN.lib.const import ignoreParams, acceptedExt, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = ''''''
    name = 'XPATH检测'
    level = Level.MIDDLE

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

        if p.query == '':
            return
        exi = os.path.splitext(p.path)[1]
        if exi not in acceptedExt:
            return

        payloads = [
            "'\"",
            "<!--"
        ]

        plainArray = [
            'MS.Internal.Xml.',
            'Unknown error in XPath',
            'org.apache.xpath.XPath',
            'A closing bracket expected in',
            'An operand in Union Expression does not produce a node-set',
            'Cannot convert expression to a number',
            'Document Axis does not allow any context Location Steps',
            'Empty Path Expression',
            'Empty Relative Location Path',
            'Empty Union Expression',
            'Expected node test or name specification after axis operator',
            'Incompatible XPath key',
            'Incorrect Variable Binding',
            'libxml2 library function failed',
            'A document must contain exactly one root element.',
            '<font face="Arial" size=2>Expression must evaluate to a node-set.',
            'Expected token \'\]\''
        ]

        regexArray = [
            "(Invalid (predicate|expression|type) in .*?\son line)",
            "(<b>\sException\sDetails:\s<\/b>System\.Xml\.XPath\.XPathException:\s'.*'\shas\san\sinvalid\stoken\.<br><br>)",
            "(<b>\sException\sDetails:\s<\/b>System\.Xml\.XPath\.XPathException:\sThis\sis\san\sunclosed\sstring\.<br><br>)",
            "(System.Xml.XPath.XPathException\:)"
        ]

        for k, v in params.items():
            if k.lower() in ignoreParams:
                continue
            data = copy.deepcopy(params)
            for payload in payloads:
                data[k] = data[k] + payload
                r = requests.get(netloc, headers=headers, params=data)
                html = r.text
                for i in plainArray:
                    if i in html:
                        out.success(url, self.name, payload="{}:{}".format(k, data[k]))
                        break
                for i in regexArray:
                    if re.search(i, html, re.I):
                        out.success(url, self.name, payload="{}:{}".format(k, data[k]))
                        break
