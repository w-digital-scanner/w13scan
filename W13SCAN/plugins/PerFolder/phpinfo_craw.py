#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/11 4:27 PM
# @Author  : w8ay
# @File    : phpinfo_craw.py

import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.helper.phpinfo_helper import get_phpinfo
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''查看此目录下是否存在phpinfo文件'''
    name = 'phpinfo遍历'
    level = Level.MIDDLE

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

        if self.response.language and self.response.language != "PHP":
            return

        variants = [
            "phpinfo.php",
            "pi.php",
            "php.php",
            "i.php",
            "test.php",
            "temp.php",
            "info.php",
        ]
        for phpinfo in variants:
            testURL = url.strip('/') + "/" + phpinfo
            r = requests.get(testURL, headers=headers)
            if "<title>phpinfo()</title>" in r.text:
                info = get_phpinfo(r.text)
                out.success(testURL, self.name, info=info)
