#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/4 6:14 PM
# @Author  : w8ay
# @File    : test_command_php_code.py
from api import scan, output

url = "http://scanbox.io/code_exec/code.php?code=a&submit=submit"
module_name = "command_php_code"
scan(url, module_name)
for item in output.collect:
    print(item)
