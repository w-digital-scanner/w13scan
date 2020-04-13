#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# @name:    Wascan - Web Application Scanner
# @repo:    https://github.com/m4ll0k/Wascan
# @author:  Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt

from re import search,I

def fingerprint(headers,content):
	_ = False
	for header in headers.items():
		_ |= search("web2py",header[1]) is not None
		if _ : break
	_ |= search(r"\<div id\=\"serendipityLeftSideBar\"\>",content) is not None
	if _ : return "Web2Py - Python Framework"