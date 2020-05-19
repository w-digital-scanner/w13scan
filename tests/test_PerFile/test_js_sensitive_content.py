#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/5/18 12:49 PM
# @Author  : w8ay
# @File    : test_js_sensitive_content.py

from W13SCAN.api import scan,KB

url = "https://dss1.bdstatic.com/5eN1bjq8AAUYm2zgoY3K/r/www/cache/news/static/protocol/https/global/js/common_43bda07.js"
url = "https://dss1.bdstatic.com/5eN1bjq8AAUYm2zgoY3K/r/www/cache/news/static/protocol/https/global/js/logic_c20cf8c.js"
url = "https://passport.baidu.com/v2/%20https:/hm.baidu.com/h.js"
module_name = "js_sensitive_content"
scan(url, module_name)
for item in KB.output.collect:
    print(item)