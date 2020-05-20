#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/5/10 9:12 PM
# @Author  : w8ay
# @File    : sqli_error.py

from lib.helper.helper_sqli import Get_sql_errors
from lib.core.common import generateResponse
from lib.core.enums import VulType
from lib.core.plugins import PluginBase
from lib.helper.helper_sensitive import sensitive_page_error_message_check


class W13SCAN(PluginBase):
    name = '基于报错SQL注入'

    def audit(self):
        _payloads = ['鎈\'"\(']
        # 载入处理位置以及原始payload
        iterdatas = self.generateItemdatas()

        # 根据原始payload和位置组合新的payload
        for origin_dict, positon in iterdatas:
            payloads = self.paramsCombination(origin_dict, positon, _payloads)
            for key, value, new_value, payload in payloads:
                r = self.req(positon, payload)
                if not r:
                    continue
                html = r.text
                for sql_regex, dbms_type in Get_sql_errors():
                    match = sql_regex.search(html)

                    if match:
                        result = self.new_result()
                        result.init_info(self.requests.url, "SQL注入", VulType.SQLI)
                        result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                          "DBMS_TYPE:{} 匹配结果:{}".format(dbms_type, match.group()), key, payload,
                                          positon)
                        self.success(result)
                        return True

                message_lists = sensitive_page_error_message_check(html)
                if message_lists:
                    result = self.new_result()
                    result.init_info(self.requests.url, "SQL注入", VulType.SQLI)
                    result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                      "需要注意的报错信息:{}".format(repr(message_lists)), key, payload,
                                      positon)
                    self.success(result)
                    return True
