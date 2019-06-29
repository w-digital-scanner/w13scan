#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/27 9:57 PM
# @Author  : w8ay
# @File    : config.py

REPOSITORY = "https://github.com/boy-hack/w13scan.git"
VERSION = '0.1'

THREAD_NUM = 20  # 线程数量

EXCLUDES = [".*\.google", ".*\.lastpass", 'baidu\.com']  # 扫描排除网址(正则表达式)
INCLUDES = [".*"]  # 扫描允许网址(正则表达式)

EXCLUDE_PLUGINS = []  # 不使用的插件
RETRY = 2  # 超时重试次数
TIMEOUT = 10  # 超时时间
