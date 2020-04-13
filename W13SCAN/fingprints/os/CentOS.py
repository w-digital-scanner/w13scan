#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# @name:    CentOS
# @author:  w8ay

from re import search, I, compile, error

from lib.core.enums import OS


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
        _ |= search(r"CentOS", headers["server"], I) is not None
    if 'x-powered-by' in headers.keys():
        _ |= search(r"CentOS", headers["x-powered-by"], I) is not None

    if _: return "CentOS", OS.LINUX
