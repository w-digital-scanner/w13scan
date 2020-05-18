#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/5/10 8:59 PM
# @Author  : w8ay
# @File    : test_idea.py

from W13SCAN.api import scan,KB

url = "http://testphp.vulnweb.com/.idea/workspace.xml"
module_name = "idea"
scan(url, module_name)
for item in KB.output.collect:
    print(item)
