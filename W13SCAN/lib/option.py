#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 1:28 PM
# @Author  : w8ay
# @File    : option.py
import os
import platform
import threading
import time
import datetime
from queue import Queue

from colorama import Fore, init as cinit

from W13SCAN.config import EXCLUDE_PLUGINS, INCLUDE_PLUGINS, SERVER_ADDR, DEBUG, INCLUDES, EXCLUDES, THREAD_NUM, LEVEL, \
    TIMEOUT, \
    RETRY, PROXY_CONFIG, ACTIVE_SCAN, PROXY_CONFIG_BOOL
from W13SCAN.lib.common import dataToStdout
from W13SCAN import VERSION, REPOSITORY
from W13SCAN.lib.data import PATH, KB, logger, conf
from W13SCAN.lib.loader import load_file_to_module
from W13SCAN.lib.spiderset import SpiderSet
from W13SCAN.thirdpart.console import getTerminalSize
from W13SCAN.thirdpart.requests import patch_all


def _set_path(root):
    PATH['root'] = root
    PATH['certs'] = os.path.join(root, 'certs')
    PATH['plugins'] = os.path.join(root, 'plugins')
    PATH["data"] = os.path.join(root, "data")


def _init_kb():
    KB['continue'] = True
    KB['registered'] = dict()
    KB['task_queue'] = Queue()
    KB["is_win"] = platform.system() == 'Windows'
    KB["spiderset"] = SpiderSet()
    KB["console_width"] = getTerminalSize()
    KB['start_time'] = time.time()
    KB['finished'] = 0
    KB["lock"] = threading.Lock()
    KB["result"] = 0
    KB["running"] = 0


def _init_plugins():
    # 加载所有插件
    _plugins = []
    for root, dirs, files in os.walk(PATH['plugins']):
        files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
        for _ in files:
            if len(INCLUDE_PLUGINS) == 1 and INCLUDE_PLUGINS[0] == 'all':
                pass
            else:
                if "loader.py" not in INCLUDE_PLUGINS:
                    INCLUDE_PLUGINS.append("loader.py")
                if _ not in INCLUDE_PLUGINS:
                    continue
            if _ in EXCLUDE_PLUGINS:
                continue
            filename = os.path.join(root, _)
            mod = load_file_to_module(filename)
            try:
                mod = mod.W13SCAN()
                getattr(mod, 'name', 'unknown plugin')
                plugin = os.path.splitext(_)[0]
                plugin_type = os.path.split(root)[1]
                if getattr(mod, 'type', None) is None:
                    setattr(mod, 'type', plugin_type)
                KB["registered"][plugin] = mod
            except AttributeError:
                logger.error('Filename:{} not class "{}"'.format(_, 'W13SCAN'))
    logger.info('Load plugin:{}'.format(len(KB["registered"])))


def _init_conf():
    cmd_line = {
        "show_version": False,
        "is_debug": None,
        "level": 0,
        "url": None,
        "url_file": None,
        "server_addr": None,
        "proxy": None,
        "timeout": 30,
        "retry": 2,
        "threads": 21,
        "excludes": [],
        "includes": [],
        "exclude_plugins": [],
        "include_plugins": [],
        "no_active": False,
        "proxy_config_bool": False
    }
    conf.update(cmd_line)
    conf["is_debug"] = DEBUG
    conf["server_addr"] = SERVER_ADDR
    conf["threads"] = THREAD_NUM
    conf["excludes"] = EXCLUDES
    conf["includes"] = INCLUDES
    conf["exclude_plugins"] = EXCLUDE_PLUGINS
    conf["include_plugins"] = INCLUDE_PLUGINS
    conf["retry"] = RETRY
    conf["timeout"] = TIMEOUT
    conf["level"] = LEVEL
    conf["no_active"] = ACTIVE_SCAN
    conf["proxy"] = PROXY_CONFIG
    conf["proxy_config_bool"] = PROXY_CONFIG_BOOL


def _merge_options(input_options):
    """
    Merge command line options with configuration file and default options.
    """
    if hasattr(input_options, "items"):
        input_options_items = input_options.items()
    else:
        input_options_items = input_options.__dict__.items()

    for key, value in input_options_items:
        if key not in conf or value not in (None, False):
            conf[key] = value


def _set_conf():
    # server_addr
    if isinstance(conf["server_addr"], str):
        defaulf = 7778
        if ":" in conf["server_addr"]:
            splits = conf["server_addr"].split(":", 2)
            conf["server_addr"] = tuple([splits[0], int(splits[1])])
        else:
            conf["server_addr"] = tuple([conf["server_addr"], defaulf])

    # threads
    conf["threads"] = int(conf["threads"])

    # conf["excludes"] = EXCLUDES
    # conf["includes"] = INCLUDES
    # conf["exclude_plugins"] = EXCLUDE_PLUGINS
    # conf["include_plugins"] = INCLUDE_PLUGINS

    # proxy
    if isinstance(conf["proxy"], str) and "@" in conf["proxy"]:
        conf["proxy_config_bool"] = True
        method, ip = conf["proxy"].split("@")
        conf["proxy"] = {
            method: ip
        }


def _init_stdout():
    # 不扫描网址
    if len(conf["excludes"]):
        logger.info("Exclude urls:{}".format(repr(conf["excludes"])))
    # 指定扫描网址
    if len(conf["includes"]) and conf["includes"][0] != ".*":
        logger.info("Include urls:{}".format(repr(conf["includes"])))
    # 不使用插件
    if len(conf["exclude_plugins"]):
        logger.info("Exclude plugins:{}".format(repr(conf["exclude_plugins"])))
    # 指定使用插件
    if len(conf["include_plugins"]) and conf["include_plugins"][0] != "all":
        logger.info("Include plugins:{}".format(repr(conf["include_plugins"])))
    # 主动探测
    no_active = 'On' if str(conf["no_active"]) == "True" else "Off"
    logger.info("Active detection mode:{}".format(no_active))


def init(root, cmdline):
    cinit(autoreset=True)
    banner()
    _set_path(root)
    _init_conf()
    _merge_options(cmdline)
    _set_conf()
    _init_kb()
    _init_plugins()
    _init_stdout()
    patch_all()


def banner():
    _ = r'''
    ❤️ (  ⚫︎ー⚫︎  ) Woo,W13Scan~
    　／　　　   ＼      
     /　　　  ○ 　\   Version:{version}   
    /　 /  　  ヽ  \   
    |　/　 　　　\　|   
     \Ԏ　         |イ  
    　卜−　　   ―イ   
    　 \　 /\　 /
    　　 ︶　 ︶
'''

    dataToStdout(Fore.GREEN + _.format(version=VERSION, git=REPOSITORY))
    qixi_eggs()


def qixi_eggs():
    data = [
        "2019-8-7",
        "2020-8-25",
        "2021-8-14"
    ]
    i = datetime.datetime.now()
    now = "{}-{}-{}".format(i.year, i.month, i.day)
    msg = '''
＞﹏＜ 又是一年七夕，善良的开发者找到女盆友没？
(ó﹏ò｡) 没有。
访问链接:https://github.com/boy-hack/w13scan/issues/new 向开发者表白～

'''
    if now in data:
        dataToStdout(Fore.RED + msg)
