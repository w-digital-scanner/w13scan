#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/7 11:18 AM
# @Author  : w8ay
# @File    : redirect.py
import copy
import os
import re
from urllib.parse import unquote, urlparse

import requests

from W13SCAN.lib.common import is_base64
from W13SCAN.lib.const import acceptedExt, Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''任意网址重定向'''
    name = '支持检查 html meta 跳转、30x 跳转、JavaScript跳转等等'
    level = Level.LOW

    def __init__(self):
        super().__init__()
        self.test_domain = "http://w13scan.io"
        self.uri = None

    def _javascript_redirect(self, response: requests.Response):
        """
        Test for JavaScript redirects, these are some common redirects:

            // These also work without the `window.` at the beginning
            window.location = "http://www.w3af.org/";
            window.location.href = "http://www.w3af.org/";
            window.location.replace("http://www.w3af.org");
            window.location.assign('http://www.w3af.org');

            self.location = 'http://www.w3af.org';
            top.location = 'http://www.w3af.org';

            // jQuery
            $(location).attr('href', 'http://www.w3af.org');
            $(window).attr('location', 'http://www.w3af.org');
            $(location).prop('href', 'http://www.w3af.org');

            // Only for old IE
            window.navigate('http://www.w3af.org');
        """
        for statement in self._extract_script_code(response):
            if self.test_domain not in statement:
                continue
            out.success(self.uri, self.name, msg="当前JavaScript脚本发现被注入url,在 {}".format(statement))

        return False

    def _extract_script_code(self, response: requests.Response):
        """
        This method receives an HTTP response and yields lines of <script> code

        For example, if the response contains:
            <script>
                var x = 1;
            </script>
            <a ...>
            <script>
                var y = 1; alert(1);
            </script>

        The method will yield three strings:
            var x = 1;
            var y = 1;
            alert(1);

        :return: Lines of javascript code
        """
        SCRIPT_RE = re.compile('<script.*?>(.*?)</script>', re.IGNORECASE | re.DOTALL)
        mo = SCRIPT_RE.search(response.text)
        if mo:
            for script_code in mo.groups():
                script_code = script_code.split('\n')
                for line in script_code:
                    for statement in line.split(';'):
                        if statement:
                            yield statement

    def _refresh_redirect(self, response: requests.Response):
        """
        Check for the *very strange* Refresh HTTP header, which looks like a
        `<meta refresh>` in the header context!

        The value for the header is: `0;url=my_view_page.php`

        :see: http://stackoverflow.com/questions/283752/refresh-http-header
        """
        if response.status_code == 200 and re.search(
                '<meta http-equiv=["\']Refresh["\'] content=["\']\d+;url=.*?["\']>', response.text,
                re.I | re.S):
            return True
        return False

    def _30x_code_redirect(self, response: requests.Response):
        """
        Test for 302 header redirects
        """
        if response.status_code in [301, 302] and "Location" in response.headers:
            url = unquote(response.headers["Location"])
            parse = urlparse(url).netloc
            if self.test_domain in parse:
                return True
        return False

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        self.uri = url = self.build_url()  # 请求完整URL

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        if p.query == '':
            return
        exi = os.path.splitext(p.path)[1]
        if exi not in acceptedExt:
            return

        if method == "GET":
            for k, v in params.items():
                if not re.match('^http.+', v, re.I):
                    ret = is_base64(v)
                    if not (ret and re.match('^http.+', ret, re.I)):
                        continue
                data = copy.deepcopy(params)
                payload = self.test_domain
                data[k] = payload
                r = requests.get(netloc, params=data, headers=headers, allow_redirects=False)
                if self._30x_code_redirect(r):
                    out.success(url, self.name, payload="{}:{}".format(k, payload), type="header头跳转")
                elif self._refresh_redirect(r):
                    out.success(url, self.name, payload="{}:{}".format(k, payload), type="html meta跳转")
                elif self._javascript_redirect(r):
                    pass
