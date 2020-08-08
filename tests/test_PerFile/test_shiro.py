#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/8/9 12:02 AM
# @Author  : w8ay
# @File    : test_shiro.py
from api import scan
from lib.core.data import KB

url = "http://127.0.0.1:8080/samples-web-1.2.4/"
module_name = "shiro"
scan(url, module_name)
for item in KB.output.collect:
    print(item)
