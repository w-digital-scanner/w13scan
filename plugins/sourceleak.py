#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 3:18 PM
# @Author  : w8ay
# @File    : sourceleak.py
from lib.common import get_parent_paths
from lib.plugins import PluginBase
from lib.data import Share
from lib.output import out
import requests


class W13SCAN(PluginBase):
    desc = '''基于流量动态查找目录下git svn等源码泄漏'''

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL
        data = self.requests.get_body_data().decode()  # POST 数据

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        path1 = get_parent_paths(url)
        flag = {
            "/.svn/all-wcprops": "svn:wc:ra_dav:version-url",
            "/.git/config": 'repositoryformatversion'
        }
        for p in path1:
            for f in flag.keys():
                _ = p.rstrip('/') + f
                if not Share.in_url(_):
                    Share.add_url(_)
                    try:
                        r = requests.get(_, headers=headers)
                        # out.log(_)
                        if flag[f] in r.text:
                            out.success("Success:" + _)
                    except Exception as e:
                        pass
