#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# @name:    Koa
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
    if 'x-powered-by' in headers.keys():
        _ |= search(r"^koa$", headers["x-powered-by"], I) is not None

    if _: return "Koa"