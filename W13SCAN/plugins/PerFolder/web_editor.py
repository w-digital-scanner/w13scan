#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/21 4:00 PM
# @Author  : w8ay
# @File    : web_editor.py


import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''收集自BBScan的插件'''
    name = "WEB 编辑器扫描"
    level = Level.LOW

    def generate(self):
        payloads = [{'path': '/fckeditor/_samples/default.html', 'tag': '<title>FCKeditor', 'content-type': 'html',
                     'content-type_no': ''},
                    {'path': '/ckeditor/samples/', 'tag': '<title>CKEditor Samples</title>', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/editor/ckeditor/samples/', 'tag': '<title>CKEditor Samples</title>', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/ckeditor/samples/sample_posteddata.php', 'tag': 'http://ckeditor.com</a>',
                     'content-type': '', 'content-type_no': ''},
                    {'path': '/editor/ckeditor/samples/sample_posteddata.php', 'tag': 'http://ckeditor.com</a>',
                     'content-type': '', 'content-type_no': ''},
                    {'path': '/fck/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.php',
                     'tag': 'init_spell()', 'content-type': 'html', 'content-type_no': ''},
                    {'path': '/fckeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellcheckder.php',
                     'tag': 'init_spell()', 'content-type': 'html', 'content-type_no': ''},
                    {'path': '/ueditor/ueditor.config.js', 'tag': 'window.UEDITOR_HOME_URL', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/ueditor/php/getRemoteImage.php', 'tag': "'tip':'", 'content-type': '',
                     'content-type_no': ''}]
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

        for payload in payloads:
            test_url = url.rstrip('/') + payload["path"]
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
