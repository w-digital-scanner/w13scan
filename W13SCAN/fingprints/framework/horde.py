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
	for header in headers:
		_ |= search(r"webmail_version=|webmail4prod=",header[1])is not None
		if _: break 
	_ |= search(r"title\=\"This site is powered by The Horde Application Framework.\" href\=\"http://horde.org\"\>",content) is not None
	_ |= search(r"Powered by \<\/font\>\<a href\=\"http://www.horde.org/\" TARGET\=_blank>",content) is not None
	_ |= search(r"/themes/graphics/horde-power1.png\" alt\=\"Powered by Horde\" title\=\"\" \/\>",content) is not None
	_ |= search(r"\<html\>\<body bgcolor\=\"\#aaaaaa\"\>\<a href\=\"icon_browser.php\"\>Application List\<\/a\>\<br \/\>\<br \/\>\<h2\>Icons for My Account\<\/h2\>",content) is not None
	_ |= search(r"\<script language\=\"JavaScript\" type\=\"text/javascript\" src\=\"/hunter/js/enter_key_trap.js\"\>\<\/script\>",content) is not None
	_ |= search(r"\<link href\=\"/mail/mailbox.php\?mailbox\=INBOX\" rel\=\"Top\" \/\>",content) is not None
	if _: return "Horde - PHP Framework"