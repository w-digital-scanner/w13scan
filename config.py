#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/27 9:57 PM
# @Author  : w8ay
# @File    : config.py

THREAD_NUM = 6  # 线程数量

EXCLUDES = [".*\.google", ".*\.lastpass", 'hacking8']  # 扫描排除网址(正则表达式)
INCLUDES = [".*"]  # 扫描允许网址(正则表达式)

# 预置header头
HEADERS = {
    'User-agent': ''
}

RETRY = 2  # 超时重试次数
