#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/27 9:57 PM
# @Author  : w8ay
# @File    : config.py

# default setting
SERVER_ADDR = ('127.0.0.1', 7778)  # 默认监听地址

THREAD_NUM = 51  # 线程数量

EXCLUDES = ["google", "lastpass", 'baidu.com', '.gov.cn']  # 扫描排除网址
INCLUDES = [".*"]  # 扫描允许网址(正则表达式)

EXCLUDE_PLUGINS = ['subdomain_found.py']  # 不使用的插件，文件名
INCLUDE_PLUGINS = ['all']  # 使用插件,文件名，all为全部

RETRY = 2  # 超时重试次数
TIMEOUT = 10  # 超时时间

LEVEL = 0  # 根据检测深度由浅入深分为1～5级别，级别越高使用插件越多。LEVEL=0代表不使用该功能，默认使用全部插件。

ACTIVE_SCAN = False  # 是否关闭主动扫描，w13scan会自动解析返回包中的链接进行扫描

# 所有扫描请求可以转发到另外一个代理上
PROXY_CONFIG_BOOL = False
PROXY_CONFIG = {
    "http": "127.0.0.1:8080",
    "https": "127.0.0.1:8080"
}

# DEBUG
DEBUG = True

# REVERSE
USE_REVERSE = False  # 使用反连平台将False改为True
REVERSE_HTTP_IP = "127.0.0.1"
REVERSE_HTTP_PORT = 9999

REVERSE_DNS = "dnslog.w13scan.hacking8.com"

REVERSE_RMI_IP = "127.0.0.1"
REVERSE_RMI_PORT = 10002

REVERSE_SLEEP = 5  # 反连后延时检测时间，单位是(秒)
