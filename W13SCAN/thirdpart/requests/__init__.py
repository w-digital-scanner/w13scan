#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/28 10:59 PM
# @Author  : w8ay
# @File    : __init__.py.py
import copy
import logging

import ssl
from urllib.parse import urlparse

from requests.cookies import RequestsCookieJar
from requests.models import Request
from requests.sessions import Session
from requests.sessions import merge_setting, merge_cookies
from requests.utils import get_encodings_from_content
from urllib3 import disable_warnings

from lib.core.data import conf


def patch_all():
    disable_warnings()
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)
    ssl._create_default_https_context = ssl._create_unverified_context
    Session.request = session_request


def session_request(self, method, url,
                    params=None, data=None, headers=None, cookies=None, files=None, auth=None,
                    timeout=None,
                    allow_redirects=True, proxies=None, hooks=None, stream=None, verify=False, cert=None, json=None):
    # Create the Request.
    merged_cookies = merge_cookies(merge_cookies(RequestsCookieJar(), self.cookies),
                                   cookies)
    default_header = {
        "User-Agent": conf.agent,
        "Connection": "close"
    }
    req = Request(
        method=method.upper(),
        url=url,
        headers=merge_setting(headers, default_header),
        files=files,
        data=data or {},
        json=json,
        params=params or {},
        auth=auth,
        cookies=merged_cookies,
        hooks=hooks,
    )
    prep = self.prepare_request(req)

    raw = ''
    p = urlparse(url)
    _headers = copy.deepcopy(prep.headers)
    if "Host" not in _headers:
        _headers["Host"] = p.netloc
    if prep.body:

        raw = "{}\n{}\n\n{}\n\n".format(
            prep.method + ' ' + prep.url + ' HTTP/1.1',
            '\n'.join('{}: {}'.format(k, v) for k, v in _headers.items()),
            prep.body)
    else:
        raw = "{}\n{}\n\n".format(
            prep.method + ' ' + prep.url + ' HTTP/1.1',
            '\n'.join('{}: {}'.format(k, v) for k, v in _headers.items()))

    proxies = proxies or {}
    if conf["proxy_config_bool"] and not proxies:
        proxies = conf["proxy"]
        if "socks4" in proxies.keys():
            _tmp_str = "socks4://" + proxies["socks4"]
            _tmp_proxy = {
                "http": _tmp_str,
                "https": _tmp_str
            }
            proxies = _tmp_proxy
        elif "socks5" in proxies.keys():
            _tmp_str = "socks5://" + proxies["socks5"]
            _tmp_proxy = {
                "http": _tmp_str,
                "https": _tmp_str
            }
            proxies = _tmp_proxy

    # prep.url = prep.url.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')
    # fix https://github.com/boy-hack/w13scan/issues/64

    settings = self.merge_environment_settings(
        prep.url, proxies, stream, verify, cert
    )

    # Send the request.
    send_kwargs = {
        'timeout': timeout or conf["timeout"],
        'allow_redirects': allow_redirects,
    }
    send_kwargs.update(settings)

    resp = self.send(prep, **send_kwargs)

    if resp.encoding == 'ISO-8859-1':
        encodings = get_encodings_from_content(resp.text)
        if encodings:
            encoding = encodings[0]
        else:
            encoding = resp.apparent_encoding

        resp.encoding = encoding

    setattr(resp, 'reqinfo', raw)
    return resp
