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
		_ |= search("zend",header[1]) is not None
		if _ : break
	_ |= search(r"\<meta name\=\"generator\" content\=\"Zend.com CMS ([\d\.]+)\"",content) is not None
	_ |= search(r"<meta name\=\"vendor\" content\=\"Zend Technologies",content) is not None 
	_ |= search(r"\"Powered by Zend Framework\"",content) is not None
	_ |= search(r" alt\=\"Powered by Zend Framework!\" \/\>",content) is not None
	if _ : return "Zend - PHP Framework"