#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/5/16 3:36 PM
# @Author  : w8ay
# @File    : test_sqli_bool.py


from W13SCAN.api import scan, KB

url = "http://scanbox.io/sql_injection/sql_num.php?id=1&submit=submit"
# url = "http://emlog6.demo/?post=1"
module_name = "sqli_bool"
conf = {
    "able": module_name
}
scan(url, module_name, conf)
for item in KB.output.collect:
    print(item)
