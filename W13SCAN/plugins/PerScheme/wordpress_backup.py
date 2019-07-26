#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/21 4:39 PM
# @Author  : w8ay
# @File    : wordpress_backup.py

import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Wordpress backup file'
    desc = ''''''
    level = Level.LOW

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

        if "/wp-content/themes/" not in resp_str:
            return
        url_lst = ['/wp-config.php.inc',
                   '/wp-config.inc',
                   '/wp-config.bak',
                   '/wp-config.php~',
                   '/.wp-config.php.swp',
                   '/wp-config.php.bak']

        for payload in url_lst:
            test_url = domain.rstrip('/') + payload
            r = requests.get(test_url, headers=headers)
            if r.status_code == 200 and '<?php' in r.text:
                out.success(test_url, self.name)
