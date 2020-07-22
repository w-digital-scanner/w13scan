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
		_ |= search("phusion passenger|rails|_rails_admin_session=", header[1]) is not None
		_ |= search("x-rails", header[0]) is not None
		if _:
			break
	_ |= search(r"<meta content=\"authenticity_token\" name=\"csrf-param\"\s?\/>\s?<meta content=\"[^\"]{44}\" name=\"csrf-token\"\s?\/>|"
				r"<link[^>]*href=\"[^\"]*\/assets\/application-?\w{32}?\.css\"|"
				r"<script[^>]*\/assets\/application-?\w{32}?\.js\"", content) is not None
	if _:
		return "Ruby on Rails - Ruby Framework"