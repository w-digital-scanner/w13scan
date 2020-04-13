#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# @name:    XAMPP
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
    _ |= _prepare_pattern("<title>XAMPP(?: Version ([\d\.]+))?</title>\;version:\1").search(content) is not None # html
    if 'author' in headers.keys():
        _ |= search(r"Kai Oswald Seidler", headers["author"], I) is not None

    if _: return "XAMPP"