#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# @name:    Java
# @author:  w8ay

from re import search, I, compile, error

from lib.core.enums import WEB_PLATFORM


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
    if 'set-cookie' in headers.keys():
        _ |= search(r"JSESSIONID", headers["set-cookie"], I) is not None

    if _: return WEB_PLATFORM.JAVA
