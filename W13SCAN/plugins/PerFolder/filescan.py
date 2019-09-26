#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 12:16 AM
# @Author  : w8ay
# @File    : filescan.py

import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''收集自BBScan的插件'''
    name = "敏感文件扫描"
    level = Level.LOW

    def generate(self):
        payloads = [{'path': '/config.inc', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/config.php.bak', 'tag': '', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/db.php.bak', 'tag': '', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/conf/config.ini', 'tag': '[', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/config.ini', 'tag': '[', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/config/config.ini', 'tag': '[', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/configuration.ini', 'tag': '[', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/configs/application.ini', 'tag': '[', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/settings.ini', 'tag': '[', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/application.ini', 'tag': '[', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/conf.ini', 'tag': '[', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/app.ini', 'tag': '[', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/config.json', 'tag': '', 'content-type': 'application/json', 'content-type_no': ''},
                    {'path': '/a.out', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/key', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/keys', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/key.txt', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/temp.txt', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/tmp.txt', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/php.ini', 'tag': '[', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/sftp-config.json', 'tag': 'password', 'content-type': 'application/json',
                     'content-type_no': ''},
                    {'path': '/index.php.bak', 'tag': '<?php', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/.index.php.swp', 'tag': '<?php', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/index.cgi.bak', 'tag': '', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/config.inc.php.bak', 'tag': '<?php', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/.config.inc.php.swp', 'tag': '<?php', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/config/.config.php.swp', 'tag': '<?php', 'content-type': '', 'content-type_no': ''},
                    {'path': '/.config.php.swp', 'tag': '<?php', 'content-type': '', 'content-type_no': ''},
                    {'path': '/.settings.php.swp', 'tag': '<?php', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/.database.php.swp', 'tag': '<?php', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/.db.php.swp', 'tag': '<?php', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/.mysql.php.swp', 'tag': '<?php', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/config.php.bkp', 'tag': '<?php', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/readme', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/README', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/readme.md', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/readme.html', 'tag': '', 'content-type': 'html', 'content-type_no': ''},
                    {'path': '/changelog.txt', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/%e6%9b%b4%e6%96%b0%e6%97%a5%e5%bf%97.txt', 'tag': '', 'content-type': 'text/plain',
                     'content-type_no': ''},
                    {'path': '/www.log', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/error.log', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/log.log', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/sql.log', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/errors.log', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/db.log', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/data.log', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/app.log', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/ntunnel_mysql.php', 'tag': 'Navicat HTTP Tunnel Tester', 'content-type': 'text/html',
                     'content-type_no': ''},
                    ]
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

        payloads = self.generate()
        success = []

        for payload in payloads:
            test_url = url.rstrip('/') + payload["path"]
            r = requests.get(test_url, headers=headers, allow_redirects=False)
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
            success.append({"url": test_url, "len": len(r.text)})

        if success:
            if len(success) < 10:
                for i in success:
                    out.success(i["url"], self.name)
            else:
                result = {}
                for item in success:
                    length = item.get("len", 0)
                    if length not in result:
                        result[length] = list()
                    result[length].append(item["url"])
                for k, v in result.items():
                    if len(v) > 5:
                        continue
                    else:
                        for i in v:
                            out.success(i, self.name)
