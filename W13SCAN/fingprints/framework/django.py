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
		_ |= search("wsgiserver/",header[1]) is not None
		_ |= search("python/",header[1]) is not None
		_ |= search("csrftoken=",header[1]) is not None
		if _ : break
	_ |= search(r"<meta name=\"robots\" content=\"NONE,NOARCHIVE\"><title>Welcome to Django<\/title>",content) is not None
	if _ : return "Django - Python Framework"