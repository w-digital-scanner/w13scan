#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/8 2:41 PM
# @Author  : w8ay
# @File    : test_xss.py

from W13SCAN.api import scan,KB

url = "http://scanbox.io/xss/reflect_xss.php?name=a&submit=submit"
url = "http://discuz.demo/2.php?u=aaa"
module_name = "xss"
scan(url, module_name)
for item in KB.output.collect:
    print(item)
