#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/22 10:25 AM
# @Author  : w8ay
# @File    : webpack.py

import requests

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'webpack源文件泄漏'

    def audit(self):
        if self.requests.suffix.lower() == '.js':
            new_url = self.requests.url + ".map"
            req = requests.get(new_url, headers=self.requests.headers)
            if req.status_code == 200 and 'webpack:///' in req.text:
                result = ResultObject(self)
                result.init_info(self.requests.url, "webpack源文件泄漏", VulType.SENSITIVE)
                result.add_detail("payload探测", req.reqinfo, generateResponse(req),
                                  "webpack:/// 在返回文本中", "", "", PLACE.GET)
                self.success(result)
