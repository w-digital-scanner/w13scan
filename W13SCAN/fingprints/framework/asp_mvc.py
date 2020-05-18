#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# @name:    Wascan - Web Application Scanner
# @repo:    https://github.com/m4ll0k/Wascan
# @author:  Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt

from re import search, I


def fingerprint(headers, content):
    _ = False
    for header in headers.items():
        _ |= header[0] == "x-aspnetmvc-version"
        _ |= header[0] == "x-aspnet-version"
        _ |= search(r"asp.net|anonymousID=|chkvalues=|__requestverificationtoken", header[1]) is not None
        if _: break
    _ |= search(r"Web Settings for Active Server Pages", content) is not None
    _ |= search(r"name=\"__VIEWSTATEENCRYPTED\" id=\"__VIEWSTATEENCRYPTED\"", content) is not None
    if _: return "ASP.NET Framework"
