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
		_ |= search("phusion passenger",header[1]) is not None
		_ |= search("rails",header[1]) is not None
		_ |= search("_rails_admin_session=",header[1]) is not None
		_ |= search("x-rails",header[0]) is not None
		if _ : break
	_ |= search(r"<meta content=\"authenticity_token\" name=\"csrf-param\"\s?\/>\s?<meta content=\"[^\"]{44}\" name=\"csrf-token\"\s?\/>",content) is not None
	_ |= search(r"<link[^>]*href=\"[^\"]*\/assets\/application-?\w{32}?\.css\"",content) is not None
	_ |= search(r"<script[^>]*\/assets\/application-?\w{32}?\.js\"",content) is not None
	if _ : return "Ruby on Rails - Ruby Framework"