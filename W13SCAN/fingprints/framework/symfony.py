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
	_ |= search(r"\"powered by symfony\"",content) is not None
	_ |= search(r"Powered by \<a href\=\"http://www.symfony-project.org/\"\>",content) is not None
	if _ : return "Symfony - PHP Framework"