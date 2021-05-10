#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: unauth.py
Author: Evi1ran
Date Created: Jan 14, 2021
Description: None
"""

# built-in imports
import copy
import difflib

# third-party imports
from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '未授权访问探测插件'
    desc = '''授权页面存在缺陷导致其他用户可以直接访问从而引发重要权限可被操作、数据库或网站目录等敏感信息泄露。'''
    seqMatcher = difflib.SequenceMatcher(None)
    SIMILAR_MIN = 0.95

    def audit(self):
        resp = self.response.text
        ret = False
        for k, v in self.requests.headers.items():
            if k.lower() in ["cookie", "token", "auth"]:
                ret = True
                break
        if not ret:
            return
        iterdatas = self.generateItemdatas()
        for origin_dict, position in iterdatas:
            if position == PLACE.COOKIE:
                for k, v in origin_dict.items():
                    request_headers_for_payload = self.del_cookie_token()
                    r = self.req(position, origin_dict, headers=request_headers_for_payload)
                    if not r:
                        continue
                    # self.seqMatcher.set_seq1(resp)
                    # self.seqMatcher.set_seq2(r.text)
                    # ratio = round(self.seqMatcher.quick_ratio(), 3)
                    # 减少内存开销
                    min_len = min(len(resp), len(r.text))
                    self.seqMatcher = difflib.SequenceMatcher(None, resp[:min_len], r.text[:min_len])
                    ratio = round(self.seqMatcher.quick_ratio(), 3)
                    if ratio > self.SIMILAR_MIN:
                        result = self.new_result()
                        result.init_info(self.requests.url, self.desc, VulType.UNAUTH)
                        result.add_detail("请求Payload", r.reqinfo, generateResponse(r),
                                          "删除{}后存在未授权访问".format(k), k, v, position)
                        self.success(result)
                        break

    def del_cookie_token(self):
        request_headers = self.requests.headers
        request_headers_for_payload = copy.deepcopy(request_headers)
        for k, v in request_headers.items():
            if k.lower() in ["cookie", "token", "auth"]:
                del request_headers_for_payload[k]
        return request_headers_for_payload
