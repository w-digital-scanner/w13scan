#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/14 11:09 AM
# @Author  : w8ay
# @File    : test_html_parse_params.py

import requests

from lib.helper.htmlparser import getParamsFromHtml

req = requests.get("https://x.hacking8.com")
resp = req.text

params = getParamsFromHtml(resp)
print(params)
