#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 1:28 PM
# @Author  : w8ay
# @File    : option.py
import os
import platform
import threading
import time
from queue import Queue

from config import EXCLUDE_PLUGINS, INCLUDE_PLUGINS
from lib.common import dataToStdout
from lib.const import VERSION, REPOSITORY
from lib.data import PATH, KB, logger, conf
from lib.loader import load_file_to_module
from lib.spiderset import SpiderSet
from thirdpart.console import getTerminalSize
from thirdpart.requests import patch_all


def _set_path(root):
    PATH['root'] = root
    PATH['certs'] = os.path.join(root, 'certs')
    PATH['plugins'] = os.path.join(root, 'plugins')


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
        "verbose": 0,
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
        "include_plugins": []
    }


def init(root, cmdline):
    banner()
    _set_path(root)
    _init_conf()
    _init_kb()
    _init_plugins()
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
    dataToStdout(_.format(version=VERSION, git=REPOSITORY))
