#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# @name:    actionhero.js
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
    _ |= _prepare_pattern("actionheroClient\.js").search(content) is not None # script
    if 'x-powered-by' in headers.keys():
        _ |= search(r"actionhero API", headers["x-powered-by"], I) is not None

    if _: return "actionhero.js"