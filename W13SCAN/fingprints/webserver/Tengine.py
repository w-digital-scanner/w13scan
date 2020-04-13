#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# @name:    Tengine
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
        _ |= search(r"Tengine", headers["server"], I) is not None

    if _: return "Tengine"


def fingerprint_assign(url, filter):
    if 'php' in filter:
        return url
    if not filter:
        return url
    return None


def fingerprint_url(url):
    payload = url + "/robots.txt"
    resp = resp.get(payload).text
    if md5(resp) == "xxxxxxx" or "emlog" in resp:
        return {
            "name": "Emlog",
            "version": "5.3.1",
            "language": "PHP",
            "database": "mysql"
        }
