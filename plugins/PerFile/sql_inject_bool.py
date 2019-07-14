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

from lib.common import prepare_url, random_str
from lib.const import acceptedExt, ignoreParams
from lib.helper.diifpage import GetRatio, findDynamicContent, getFilteredPageContent
from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '基于布尔判断的SQL注入'
    desc = '''目前仅支持GET方式的请求'''

    def init(self):
        self.retry = 5  # 重试次数
        self.dynamic = []
        self.seqMatcher = difflib.SequenceMatcher(None)

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

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        if method == 'GET':
            # 从源码中获取更多链接
            if p.query == '':
                return
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return

            self.init()
            # 重新请求一次获取一次网页
            r = requests.get(url, headers=headers)
            try:
                self.seqMatcher.set_seq1(resp_str)
                self.seqMatcher.set_seq2(r.text)
                radio = self.seqMatcher.quick_ratio()
            except MemoryError:
                return

            if radio <= 0.98:
                self.findDynamicContent(resp_str, r.text)
                count = 0
                while 1:
                    count += 1
                    if count > self.retry:
                        return
                    r = requests.get(url, headers=headers)
                    self.findDynamicContent(resp_str, self.removeDynamicContent(r.text))

            sql_flag = [
                "/**/and'{0}'='{1}'",
                "'and'{0}'='{1}",
                '"and"{0}"="{1}',
            ]
            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                data = copy.deepcopy(params)
                for flag in sql_flag:
                    # false page
                    is_inject = False
                    payload2 = v + flag.format(random_str(1) + 'a', random_str(1) + 'b')
                    data[k] = payload2
                    r2 = requests.get(netloc, params=data, headers=headers)
                    html1 = self.removeDynamicContent(r2.text)
                    ratio = 1.0
                    try:
                        ratio *= GetRatio(resp_str, html1)
                        # self.seqMatcher.set_seq1(resp_str or "")
                        # self.seqMatcher.set_seq2(html1 or "")
                        # ratio *= self.seqMatcher.quick_ratio()  # true false
                        if ratio > 0.98:
                            continue
                    except (MemoryError, OverflowError):
                        continue

                    # true page
                    rand_str = random_str(2)
                    payload1 = v + flag.format(rand_str, rand_str)
                    data[k] = payload1
                    r = requests.get(netloc, params=data, headers=headers)
                    html2 = self.removeDynamicContent(r.text)
                    try:
                        # self.seqMatcher.set_seq1(html2 or "")
                        # self.seqMatcher.set_seq2(html1 or "")
                        # ratio2 = self.seqMatcher.quick_ratio()  # true false
                        ratio2 = GetRatio(html1, html2)
                    except (MemoryError, OverflowError):
                        continue

                    try:
                        # self.seqMatcher.set_seq1(html2 or "")
                        # self.seqMatcher.set_seq2(resp_str or "")
                        # ratio3 = self.seqMatcher.quick_ratio()  # true true
                        ratio3 = GetRatio(resp_str, html2)
                    except (MemoryError, OverflowError):
                        continue
                    if (0.1 > ratio - ratio2 > -0.1) and ratio3 > ratio - 0.05 and ratio3 > ratio2 - 0.5:
                        is_inject = True
                    if not is_inject:
                        originalSet = set(getFilteredPageContent(resp_str, True, "\n").split("\n"))
                        trueSet = set(getFilteredPageContent(html2, True, "\n").split("\n"))
                        falseSet = set(getFilteredPageContent(html1, True, "\n").split("\n"))

                        if originalSet == trueSet and trueSet != falseSet:
                            candidates = trueSet - falseSet
                            if candidates:
                                candidates = sorted(candidates, key=len)
                                for candidate in candidates:
                                    if re.match(r"\A[\w.,! ]+\Z",
                                                candidate) and ' ' in candidate and candidate.strip() and len(
                                        candidate) > 10:
                                        is_inject = True
                                        break
                    if is_inject:
                        out.success(url, self.name, raw=[r2.raw, r.raw],
                                    payload1="{}:{}".format(k, payload1), payload2="{}:{}".format(k, payload2))
                        break
