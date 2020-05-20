#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/27 9:57 PM
# @Author  : w8ay
# @File    : config.py

# Default setting
THREAD_NUM = 31  # 线程数量

EXCLUDES = ["google", "lastpass", '.gov.']  # 扫描排除网址

RETRY = 2  # 超时重试次数
TIMEOUT = 10  # 超时时间
LEVEL = 3  # 发包等级

# 所有扫描请求可以转发到另外一个代理上
PROXY_CONFIG_BOOL = False
PROXY_CONFIG = {
    "http": "127.0.0.1:8080",
    "https": "127.0.0.1:8080"
}
ABLE = []  # 允许使用的插件
DISABLE = []  # 不允许使用的插件

XSS_LIMIT_CONTENT_TYPE = True  # 限制xss的content-type，为True时限制content-type为html，为False不限制

# DEBUG
DEBUG = False

# REVERSE
USE_REVERSE = False  # 使用反连平台将False改为True
REVERSE_HTTP_IP = "127.0.0.1"  # 回连http IP地址，需要改为服务器ip，不能改为0.0.0.0，因为程序无法识别
REVERSE_HTTP_PORT = 9999  # 回连http端口

REVERSE_DNS = "dnslog.w13scan.hacking8.com"

REVERSE_RMI_IP = "127.0.0.1"  # Java RMI 回连IP,需要改为服务器ip，不能改为0.0.0.0，因为程序无法识别
REVERSE_RMI_PORT = 10002  # Java RMI 回连端口

REVERSE_SLEEP = 5  # 反连后延时检测时间，单位是(秒)
