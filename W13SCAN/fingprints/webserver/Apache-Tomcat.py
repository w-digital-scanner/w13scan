#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# @name:    Apache Tomcat
# @author:  w8ay

from re import search, I, compile, error


def _prepare_pattern(pattern):
    """
    Strip out key:value pairs from the pattern and compile the regular
    expression.
    """
    regex, _, rest = pattern.partition('\;')
    try:
        return compile(regex, I)
    except error as e:
        return compile(r'(?!x)x')


def fingerprint(headers, content):
    _ = False
    if 'server' in headers.keys():
        _ |= search(r"Apache-Coyote(/1\.1)?\;version:\1?4.1+:", headers["server"], I) is not None
    if 'x-powered-by' in headers.keys():
        _ |= search(r"Tomcat(?:-([\d.]+))?\;version:\1", headers["x-powered-by"], I) is not None

    if _: return "Tomcat"
