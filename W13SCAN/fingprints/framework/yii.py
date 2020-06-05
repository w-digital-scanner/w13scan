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
	_ |= search(r"<a href=\"http://www.yiiframework.com/\" rel=\"external\">Yii Framework<\/a>",content) is not None
	_ |= search(r">Yii Framework<\/a>",content) is not None
	if _ : return "Yii - PHP Framework"