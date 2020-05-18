#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# @name:    PHP
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
    _ |= _prepare_pattern("\.php(?:$|\?)").search(content) is not None  # url
    if 'server' in headers.keys():
        _ |= search(r"php/?([\d.]+)?\;version:\1", headers["server"], I) is not None
    if 'set-cookie' in headers.keys():
        _ |= search(r"PHPSESSID", headers["set-cookie"], I) is not None
    if 'x-powered-by' in headers.keys():
        _ |= search(r"php/?([\d.]+)?\;version:\1", headers["x-powered-by"], I) is not None

    if _: return WEB_PLATFORM.PHP
