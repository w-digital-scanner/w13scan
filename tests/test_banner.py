#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/20 10:51 AM
# @Author  : w8ay
# @File    : test_banner.py
import random

from colorama.ansi import code_to_chars
from cowpy.cow import get_cow, milk_random_cow

# for i in range(100):
from lib.core.common import random_colorama

cow = get_cow()
msg = "w13scan v1.0"

for i in range(50):
    sfw = True
    s = milk_random_cow(msg, sfw=sfw)
    #     print(s)
    # print(s)
    test = "aa\t\tabccc"
    s = random_colorama(s)
    print(s)
