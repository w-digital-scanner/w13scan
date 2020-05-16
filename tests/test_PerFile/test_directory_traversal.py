#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/5/16 6:05 PM
# @Author  : w8ay
# @File    : test_directory_traversal.py.py


from W13SCAN.api import scan, KB

url = "http://demo.aisec.cn/demo/aisec/html_link.php?id=index.html"
module_name = "directory_traversal"
conf = {
    "able": module_name
}
scan(url, module_name, conf)
for item in KB.output.collect:
    print(item)