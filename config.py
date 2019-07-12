#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/27 9:57 PM
# @Author  : w8ay
# @File    : config.py


SERVER_ADDR = ('127.0.0.1', 7778)  # 默认监听地址

THREAD_NUM = 11  # 线程数量

EXCLUDES = [".*\.google", ".*\.lastpass", 'baidu\.com']  # 扫描排除网址(正则表达式)
INCLUDES = [".*"]  # 扫描允许网址(正则表达式)

EXCLUDE_PLUGINS = []  # 不使用的插件，文件名
INCLUDE_PLUGINS = ['all']  # 使用插件,文件名，all为全部

RETRY = 2  # 超时重试次数
TIMEOUT = 10  # 超时时间

LEVEL = 0  # 根据检测深度由浅入深分为1～5级别，级别越高使用插件越多。
DEBUG = False  # DEBUG模式会看到报错信息

# 所有扫描请求可以转发到另外一个代理上
PROXY_CONFIG_BOOL = False
PROXY_CONFIG = {
    "http": "127.0.0.1:8080",
    "https": "127.0.0.1:8080"
}

if LEVEL >= 1:
    # 等级为1，只使用简单，对网站无影响的插件
    INCLUDE_PLUGINS = []
    INCLUDE_PLUGINS.extend(['jsonp.py', 'cors.py', 'errorpage.py', 'directory_browse.py',
                            'js_sensitive_content.py', 'analyze_parameter.py', 'normal_page.py', 'redirect.py',
                            ])
if LEVEL >= 2:
    INCLUDE_PLUGINS.extend(
        ['sql_inject_error.py', 'sql_inject_time.py', 'directory_browse.py', 'repository_leak.py', 'errorpage.py',
         'redirect.py'])

# DEBUG
# DEBUG = True
# INCLUDE_PLUGINS = ['php_real_path.py', 'js_sensitive_content.py', 'sql_inject_bool.py', 'sql_inject_error.py',
#                    'sql_inject_int.py', 'sql_inject_time.py']
# THREAD_NUM = 1
