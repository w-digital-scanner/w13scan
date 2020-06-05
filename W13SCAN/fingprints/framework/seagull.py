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
	_ |= search(r"<meta name=\"generator\" content=\"Seagull Framework\" \/>",content) is not None
	_ |= search(r"Powered by <a href=\"http:\/\/seagullproject.org[\/]*\" title=\"Seagull framework homepage\">Seagull PHP Framework<\/a>",content) is not None
	_ |= search(r"var SGL_JS_SESSID[\s]*=",content) is not None
	if _: return "Seagull - PHP Framework"