#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/4 10:18 PM
# @Author  : w8ay
# @File    : loader.py
from urllib.parse import urlparse

import requests

from lib.controller.controller import task_push
from lib.core.common import isListLike, get_links, get_parent_paths
from lib.core.data import conf, KB
from lib.core.enums import WEB_PLATFORM, OS
from lib.core.plugins import PluginBase
from lib.core.settings import logoutParams, notAcceptedExt


class W13SCAN(PluginBase):
    type = 'loader'
    desc = '''Loader插件对请求以及响应进行解析，从而调度更多插件运行'''
    name = 'plugin loader'

    def audit(self):
        headers = self.requests.headers
        url = self.requests.url
        resp_str = self.response.text

        if conf.no_active:
            # 语义解析获得参数,重新生成新的fakereq,fakeresps
            pass

        # fingerprint basic info
        exi = self.requests.suffix.lower()
        if exi == ".asp":
            self.response.programing.append(WEB_PLATFORM.ASP)
            self.response.os.append(OS.WINDOWS)
        elif exi == ".aspx":
            self.response.programing.append(WEB_PLATFORM.ASPX)
            self.response.os.append(OS.WINDOWS)
        elif exi == ".php":
            self.response.programing.append(WEB_PLATFORM.PHP)
        elif exi == ".jsp" or exi == ".do" or exi == ".action":
            self.response.programing.append(WEB_PLATFORM.JAVA)

        for name, values in KB["fingerprint"].items():
            if not getattr(self.response, name):
                _result = []
                for mod in values:
                    m = mod.fingerprint(self.response.headers, self.response.text)
                    if isinstance(m, str):
                        _result.append(m)
                    if isListLike(m):
                        _result += list(m)
                if _result:
                    setattr(self.response, name, _result)
        # fingerprint basic end

        if KB["spiderset"].add(url, 'PerFile'):
            task_push('PerFile', self.requests, self.response)

        # Send PerScheme
        p = urlparse(url)
        domain = "{}://{}".format(p.scheme, p.netloc)
        if KB["spiderset"].add(domain, 'PerScheme'):
            # todo perscheme fake req and resp
            task_push('PerScheme', self.requests, self.response)

        if conf["no_active"]:
            return
        # Collect from response
        links = get_links(resp_str, url, True)
        for link in set(links):
            is_continue = True
            for item in logoutParams:
                if item in link.lower():
                    is_continue = False
                    break
            for item in notAcceptedExt:
                if link.endswith(item):
                    is_continue = False
                    break

            if not is_continue:
                continue

            # 去重复
            if not KB["spiderset"].add(link, 'get_links'):
                continue
            try:
                # 超过5M拒绝请求
                r = requests.head(link, headers=headers)
                if "Content-Length" in r.headers:
                    if int(r.headers["Content-Length"]) > 1024 * 1024 * 5:
                        raise Exception("length > 5M")
                r = requests.get(link, headers=headers)
                req = FakeReq(link, headers)
                resp = FakeResp(r)
            except Exception as e:
                continue

            if KB["spiderset"].add(resp._url, 'PerFile'):
                task_push('PerFile', req, resp)

        # Collect directory from response

        urls = set(get_parent_paths(url))
        for link in set(links):
            urls |= set(get_parent_paths(link))
        for i in urls:
            if not KB["spiderset"].add(i, 'get_link_directory'):
                continue
            try:
                r = requests.get(i, headers=headers)
                req = FakeReq(i, headers)
                resp = FakeResp(r)
            except:
                continue
            if KB["spiderset"].add(resp._url, 'PerFolder'):
                task_push('PerFolder', req, resp)
