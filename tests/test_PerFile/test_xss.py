#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/8 2:41 PM
# @Author  : w8ay
# @File    : test_xss.py

from api import scan, output

url = "https://passport.house.163.com/sign/login.html?&scope=userinfo&response_type=code&redirect_uri=https%3A%2F%2Fesf.house.163.com%2Ffurion%2Fconsumer%2Fcode%3Furl%3Dhttps%253A%252F%252Fesf.house.163.com&state=cb5f7795e47a0d91608c77387c38b82f&client_id=c27585tefc45465eqw23240c263915fv"
module_name = "xss"
scan(url, module_name)
for item in output.collect:
    print(item)
