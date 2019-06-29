#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 4:46 PM
# @Author  : w8ay
# @File    : directory_browse.py
from lib.common import get_parent_paths, get_links
from lib.plugins import PluginBase
from lib.data import Share
from lib.output import out
import requests


class W13SCAN(PluginBase):
    name = '目录遍历插件'
    desc = '''遍历每个目录，查看是否可以直接访问'''

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL
        data = self.requests.get_body_data().decode()  # POST 数据

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        path1 = get_parent_paths(url)
        urls = set(path1)
        for link in get_links(resp_str, url, True):
            path1 = get_parent_paths(link)
            urls |= set(path1)

        flag_list = [
            "index of",
            "directory listing for",
            " - /"
        ]
        for p in urls:
            if not Share.in_url(p):
                Share.add_url(p)
                try:
                    r = requests.get(p, headers=headers)
                    for i in flag_list:
                        if i.lower() in r.text:
                            out.success(_, self.name)
                            break
                except Exception as e:
                    pass
