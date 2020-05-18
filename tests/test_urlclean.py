#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/17 2:20 PM
# @Author  : w8ay
# @File    : test_urlclean.py
import copy
from urllib.parse import urlparse, urlunparse
import os

from lib.core.common import splitUrlPath

url = "http://test.test/index.php/getlist/index/id/1/order-by/desc/"
url2 = "http://test.test/index.php/getlist/index/id/1/order-by/desc.html"



print(splitUrlPath(url))
print(splitUrlPath(url, False))
print(splitUrlPath(url2))
print(splitUrlPath(url2, False))
